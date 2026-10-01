# BUSBAR 1.6.0 — THE DOCUMENT

**This file is the whole specification.** It replaced and deleted five predecessors in `49ab4aca2`
(`VISION-1.6.0.md`, `1.6.0-plane-extraction-LOCKED.md`, `DECISIONS.md`, `1.6.0-PLAN.md`,
`1.6.0-plane-abi-taxonomy.md`). If you are a new session: read **Part 0**, say "got it", and drill
into the Part you need. Nothing else in `docs/design/` outranks this file.

**Authority order inside this document** (was DECISIONS #14, now structural):
Part 1 (Vision/Laws) > Part 3 (Plane seam) > Part 2 (the 85 Locked Decisions) > Part 5 (Execution plan).
Where a checklist disagrees with a Law or an owner ruling, the Law and the owner win. **THE DESIGN —
kernel and plugins** (Part 0, owner-approved 2026-09-27) is the one place the kernel<>plugins design
lives; any passage elsewhere that disagrees with it is marked SUPERSEDED and yields to it.

**How to cite.** All 85 decision rows keep their numbers verbatim — they are cited from source
comments, `qa/*.toml` gate ledgers, workflow YAML and commit messages. `#41`, `#67`, `#78` and the
rest mean exactly what they meant before this collapse. Cite a row; never re-litigate it.

| Part | What it is | Who wrote it |
|---|---|---|
| 0 | Orientation — the whole release in one screen, and THE DESIGN (kernel and plugins) | new |
| 1 | The Vision: Law 0 and Laws 1–7 | verbatim |
| 2 | The 85 Locked Decisions (LAW + enforcing gate) | verbatim + 79-85 new |
| 3 | The plane-extraction seam, LOCKED v4 | verbatim |
| 4 | The plane ABI neutral taxonomy, v5 | verbatim |
| 5 | The DEV-GREEN definition and execution rulings (the plan itself is the TODO) | revised 2026-09-30 |
| 6 | The release engine: branches, turnstile, train, Latchkey, cost | new |
| 7 | Current state → points at the TODO's PATH TO DEV-GREEN | revised 2026-09-30 |
| A–E | Appendices: the memory ABI in detail; the dated ruling log; the plane driver; the boot loop; the transport/binding matrix | folded 2026-09-30 |

---

# PART 0 — READ THIS FIRST

## What 1.6.0 is

> **OWNER-RATIFIED 2026-09-23 — THE BENCHMARK.** The owner read this statement and said:
> *"LITERALLY PERFECT — LOCK THIS IN AS GOLD. I couldn't have said what 1.6.0 is any better.
> If ever in doubt this is the benchmark."* When any plan, gate, agent brief or design argument
> is unsure what the release IS, it is measured against the text in this blockquote — not against
> a checklist, not against a wave table, and not against a later restatement. Nothing below may
> contradict it; where something does, this wins.
>
> **Today (1.5.5), busbar is one big program that has hard-coded knowledge of every protocol it
> speaks.** The core, the protocol handlers, and every dialect are mangled together in a single
> crate. If you want busbar to speak something new, you edit core.
>
> **1.6.0 turns that inside out.** Core becomes a thin engine that knows nothing about any specific
> protocol. Everything that knows about a protocol becomes a **plugin**. You run core, and you drop
> in plugins. Core treats all of them identically and genuinely does not know whether you've loaded
> zero plugins or a hundred.
>
> That's the whole release in one sentence: **core stops being a monolith that knows about protocols
> and becomes a thin engine that hosts plugins.**
>
> ### The pieces
>
> There are **7 kinds of plugin**: store, secret, auth, hook, export, **plane**, **transport**.
>
> A **plane** is "how to speak a family of protocols" — there are 5: llm, mcp, a2a, streaming,
> decisions. A **transport** is "how to move the bytes." A **dialect** (say, OpenAI's wire format vs
> Anthropic's) lives *inside* a plane — the llm plane has 6 of them. Adding a dialect means editing
> that plane's crate. **Core doesn't change at all.** That's the test of whether we got it right.
>
> **Two rules govern every plugin, and there is no third:**
> 1. It can be compiled into the binary **or** dropped into a `plugins/` folder — same contract,
>    same loading path, your choice at packaging time.
> 2. It talks to core **only** over the ABI.
>
> ~~Two lanes exist on that one seam, chosen by how hot the path is: plane and transport get an
> in-memory `repr(C)` lane measured in sub-microseconds; the other five get JSON. Each kind is bound
> to exactly one lane — it's a cost decision, not a second contract.~~
> **SUPERSEDED 2026-09-27 by THE DESIGN §11.1–§11.2** (owner: *"Plugins speak Memory ABI ONLY."*):
> every kind speaks the memory ABI; seven ABIs, one per kind, share one mechanism.
>
> ### What must NOT change
>
> This is the part that makes it hard rather than just laborious.
>
> **A customer running 1.6.0 with only the LLM plane must get byte-identical behaviour to published
> 1.5.5.** Same config schema, same wire bytes, same everything — proven cell by cell against the
> real 1.5.5 binary. The four new planes are purely additive and off by default. That oracle is
> never waived, and a genuine divergence gets parked for the owner, never self-approved.
>
> **And money.** Two independent systems — the ledger and the ratecard. Money is a *view*:
> `money = f(ledger, ratecard)`, computed when someone asks. Nothing ever stores a dollar amount.
> So money is never wrong — if a number looks wrong, either the ledger is wrong or the ratecard is
> wrong, and every finding has to name which.

### How core talks to a plane and to a transport — OWNER-RATIFIED 2026-09-23

> This is the WHOLE contract. Core needs to know nothing else about how either one works.
>
> **A plane.** Core knows it has N plugins of kind `plane`. It asks each one for its **config verb**
> and hands that plane the matching config section. That is all. Core does not know what the plane
> does with it. **If two planes claim the same verb, boot fails with an error** — ambiguity is never
> resolved by picking a winner.
>
> **A transport.** Core knows it has N plugins of kind `transport`. A plane says *"get me http"*.
> Core asks every transport *"who deals with http?"* and each transport answers with what it owns.
> That is all. **Core never knows what `http`, `https` or `grpc` mean** — those strings are data
> passing through it from a plane to a transport. If two transports claim the same scheme, boot
> fails with an error.
>
> **The single rule underneath both:** core holds NO list of instances. For every kind it knows only
> how many plugins it has and what kind each is; it asks each plugin what it claims, and it refuses
> at boot when two plugins claim the same thing.
>
> **WHERE AN INSTANCE NAME IS STILL ALLOWED — and this is the sharp line.** There are two
> distributions: `core` alone, into which you drop the plugins you want; and `default`, which is core
> plus the standard plugins compiled in, with more dropped in later. A build has to know which
> plugins it ships with. So a **Cargo manifest, a feature name, a build script, and the composition
> root's dependency list MAY name planes and transports** — that is packaging stating what is in the
> box.
>
> **IN RUST SOURCE, ONLY THE THING ITSELF MAY NAME ITSELF.** `busbar-plane-llm` may say `llm` and may
> name its own six dialects, because they are inside it. `busbar-transport-http` may say `http`.
> Nothing else may — not the kernel, not the contract crate, not the loader, not admin, and **not a
> sibling**: `busbar-transport-grpc` naming `http` is a violation exactly as `busbar-kernel` naming
> `mcp` is, because grpc is naming a transport that is not itself. A violation counts however it is
> spelled — a field, a const, a match arm, a string literal, a function parameter, or a type.
>
> This is why the seven transport-to-transport dependency edges are an architecture defect and not a
> convenience: `grpc -> http`, `grpc -> tcp`, `sse -> http`, `tls -> tcp`, `tls -> unit-transport-key`,
> `ws -> http`, `ws -> tcp`. Each is one transport reaching for another by name instead of asking core.
>
> That is why `plane-purity` scans `src/` and never `Cargo.toml` — the gate already encodes this
> rule. What is wrong with it is its denominator, not its judgement.

(Note, 2026-09-30: of those edges, `sse` and `tls` are no longer transports — sse is an http claim and TLS
lives in the connector, §5 — so the rule stands on the remaining ones.)

### The same thing again, in the document's own vocabulary


One sentence: **core stops being a monolith that knows about protocols, and becomes a thin engine
that hosts plugins.**

1.5.5 was one `busbar` crate with the core, the planes and every dialect mangled together, and core
carried special-case knowledge of individual protocols. That entanglement is the defect 1.6.0 cures.
In 1.6.0 you run **core** and drop in **plugins**; core does everything the same way for everything
and does not know or care whether there are zero planes or a hundred.

## THE DESIGN — kernel and plugins (owner-approved 2026-09-27)

> This is the design of 1.6.0's kernel and plugins, in one place. The owner approved it on
> 2026-09-27. Part 2 rows point here as "THE DESIGN §N"; where any other text in this file
> disagrees with this section, this section wins. The build order is in `1.6.0-TODO.md`,
> KERNEL<>PLUGINS phase. §11 is the plugin ABI the owner locked on 2026-09-27; where §1–§10 disagree
> with §11, §11 wins.

### 1. The kernel

**The kernel is the teller loop.** Every request passes the same ordered steps: arrival → decode →
authenticate → verify → approve → admit → route → meter → audit → exit. Everything the kernel owns
is a step of that loop or a service a step uses:

- the **valves**: admission, the egress allow-list and pin, the breaker, the budget, the mint ceiling;
- the **meters**: bytes, units, fees;
- the **badge press**: the token stamp and auth verify (`keys`, core's own signed-key verifier, is
  part of it and is not a plugin);
- **one clock**, which also drives every plugin's `tick`.

Plugins are called from the loop's steps.

**It is a byte pump.** What the kernel sees of plugin traffic is opaque bytes on numbered
connections (`ConnId`). Nothing in the kernel parses or understands a protocol, a plugin name or a
plane concept; that knowledge lives in a plugin or in the connector (§5). The test for every change:
*does this make the kernel smarter about what is attached? If yes, it is wrong.* It is a dumb busbar.

**It speaks kinds, never instances.** The kernel knows what planes, transports, exporters and the
other kinds *do* — per-kind contracts, registries, host services, and loop steps that call kinds.
It never knows which instance is attached, which protocol it speaks or which dialect.

**It names no plugin.** It finds plugins only by enumerating the linked rows and the `plugins/`
directory. It holds no list of instance names and makes no name check. A behaviour one instance
needs is a fact that instance declares (§2). Aliases, old-name migrations and strategy words are
declared by the plugin that owns them or sit in the root legacy table; refusal texts and
`--validate` lists that name instances are rendered from the plugins' rows, byte-identical to
1.5.5. Kernel tests use kind-neutral doubles. `literal` and `none` are core secret grammar. The one
place a plugin name appears is the composition root's manifest: its `Cargo.toml` dependency, its
feature and its linked row. The cleanliness crates (§8) obey the same rule.

**Every plane gets every capability.** Owner, 2026-09-02: *"breakers, hooks, auditing — list all
the core functionality. outside should ONLY BE Auth, Store, Protocols, i.e. Plugins. Any plugin gets
all functionality. LLM == MCP == A2A — just different protocols not different pathway through engine
at all."* The breaker, the hook tap and gate, metrics, the audit record and outbound auth apply to
every plane the same way. A capability one plane has and a sibling plane lacks is a gap to close,
never a difference to argue for.

**The audit step writes one fixed record, for every plane.** Owner (on or before 2026-09-04): *"The
audit record is a fixed schema, required for every plane, never optional or plane-chosen"* — who
(principal), what (unit key, op class, verified destination), when (wall + monotonic, node),
outcome (`UnitEnd`, step), amount, controls (hold/settle seqs, slice, hooks applied), integrity
(prev hash). The amount is the unit's counts plus the rate-card version, never a price (#43,
#77(3)). Content — prompts, tool arguments, audio, transcripts — never enters the chain for any
plane; a customer who wants content kept gets it from an export plugin into their own sink under
their own retention (#82).

**Admission bounds live work; nothing evicts it.** An active work handle is never evicted: a real
bound on concurrent live work is a refusal at admission, because *"a refusal is a fact the caller
can act on and an eviction is not"* (2026-09-05). Retention bounds only settled handles, and the
sweep runs from a submit, never from a read or a timer. Exempt origins stay exempt: a handshake, a
tick and a kernel-verb unit draw no concurrency or budget lease, so the operator surface still
answers while a group is capped out.

**Multi-node is the design** (owner register, on or before 2026-09-04). Nodes share one store, as in
1.5.5. Admission cells are node-local — hydrated once at boot, never re-read — so N nodes admit up
to ≈ N× a cap; that is the 1.5.5 bound (PB-59), and 1.6.0 keeps it.

*Proven by:* kernel, contract and cleanliness crates × every kind instance = 0 (the census reads
`plugins.yaml` aliases and manifest names, so external plugins count); the kind-isolation gate
counts instance ids, never kind words; teller-steps; `crates/busbar/tests/capability_equality.rs`
and `plane_isomorphism.rs` over every plane; the retention-sweep test that keeps every active
handle.

### 2. Plugins

**Seven kinds:** store, secret, auth, hook, export, plane, transport. Everything that is not the
loop is a plugin. Each plugin lives in its own repo (§9), is compiled in or dropped in over the same
contract and the same loading path, and talks to core only over its kind's memory ABI (§11). A
compiled-in plugin exports the same door and is called through the same table as a dropped-in one.

**A plugin loads if and only if config uses it. There are no special plugins.** What counts as a
use follows the three classes of root key (§4): a plane's verb; a `module:` (or alias) named by an
entry in a kind's definition map, or a reference using a plugin's sugar (`{env: X}`, `{file: Y}`);
a URL scheme a transport claims; a provider's auth style (§6); a pool's strategy word (e.g.
`cheapest`); a fetch URL. env and file secrets are ordinary plugins (`busbar-secret-env`,
`busbar-secret-file`), linked in the default build; a core + vault build that never references
them never loads them. The kernel resolves a secret reference by asking the loaded secret plugins;
a reference to a source that is not loaded refuses boot, naming the missing module. The sugar
parser is config-level, in the contract, and resolves among the loaded secret plugins; `api_key_env`
keeps its 1.5.5 refusal and migration; a plane's own secret sites go wherever a host-held replacement
exists, and a gate lists the ones still owed (WIRE-SECRET, ARCHITECT ruling 2026-09-29).

**One Statement.** Every plugin carries one Statement, emitted by the door macro and embedded in its
signed manifest. Each fact is declared once; anything derivable is derived.

| Field | Carries |
|---|---|
| `name`, `kind`, `version`, `abi` | the manifest name; its kind's ABI version (§11.2) ~~one contract-ABI range~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.2 |
| `marks` | exclusive: `one_instance`, auth provider name and alias, auth style names, hook words. Shared: carrier class consumed, `ephemeral`, `catalog`, `blocks`. Section, path and scheme marks are derived from `sections`, inbound needs and transport claims |
| `rewrites` | live aliases and sugar (`{env: X}`, `api_key_env` → `api_key: {env: …}`, strategy words) |
| `settings` | schema, defaults, required-ness, secret fields, `target_from`, `trust_from`. A plugin with no settings and no needs is a bootstrap plugin |
| `sections` | `owns`: its config verb, entry patterns and the reserved `pools` sub-key. `consumes`: read-only, positioned |
| `needs` | its connections (§5) |
| `declares` | metric series, diagnostics, structured answers |
| planes only | `route_cost [(meter_class, weight)]`; `dialect_auth [(protocol, default style)]` — the outbound default only; the inbound default rides the claims (THE DESIGN §6, "Auth points and guest lists") |

Retired names (`redis` → valkey, `tokens`/`static-tokens`) and migrations for plugins that are not
in the build (1.4.x `governance.db_path` → sqlite) live in the root legacy table,
`[package.metadata.busbar.legacy]`, generated from `plugins.yaml`.

**No legacy loading (§11.8).** A published 1.5.5 JSON-contract plugin does not load: boot refuses it
with a message naming the rebuild against the 1.6.0 SDK. The loader accepts only the current version
of each kind and refuses newer-than-host. ~~**Published 1.5.5 plugins keep loading** through the
legacy-artifact class, beside 1.6.0 plugins (owner, 2026-09-19 and PB-11). The one exception (owner,
2026-09-27): a published plugin that opens its own sockets cannot sit behind the connector, so it is
refused at load with a message naming the plugin release that fixes it — an accepted difference.~~
SUPERSEDED 2026-09-27 by THE DESIGN §11.8.

**One row, one door, one registry.** A plugin is one row, `LinkedRow{statement, door}`. Linked and
dropped-in rows cross the same boundary. There is one door macro, `busbar_contract::export_plugin!`,
with an arm per kind (transport has two: carrier and framer). One `PluginRegistry` admits every
plugin's marks, rebuilt per generation and swapped atomically; its refusals come from one template.
Overlapping path claims resolve by precedence before anything is refused (CG-62, 2026-09-05): of
two path-family claims of different specificity, the most specific wins by the sealed order; only an
overlap at equal precedence between claims with compatible scheme sets refuses boot, and claims with
disjoint scheme sets never overlap. A plane's inbound paths are compile-time claims in its
Statement; a configured address naming a path the plane does not claim refuses boot at validation
(CG-17, 2026-09-05: the mcp mount is fixed at `/mcp`).

**Unsafe code, per kind.** Plane, hook, auth (inbound and outbound) and secret plugins are
`#![forbid(unsafe_code)]`; transport, loader, store and export crates are `#![deny(unsafe_code)]`
with a reviewed allow-list. Plugins never mount themselves: declared routes are mounted by the
kernel.

**What differs per kind is only what is essential:**

Every kind is on the memory ABI (§11.1); the Lane column is SUPERSEDED 2026-09-27 by THE DESIGN
§11.1. The Contract column names the SDK's typed wrapper (`abi/sdk/`) over the kind's table in
`busbar-contract/src/abi/<kind>/` (§11.5).

| Kind | Lane | Contract | Host services it adds |
|---|---|---|---|
| store | memory ~~COLD~~ | `RecordStore` | — |
| secret | memory ~~COLD~~ | `SecretModule` | — |
| auth | memory ~~COLD~~ | inbound `AuthModule + LoginModule`; outbound `open`, the per-request auth-fields call, `refresh`, `tick` (§6) ~~`open_bound`, `decorate`, `tick`~~ | `tick` |
| hook | memory ~~COLD~~ | `HookHandler` | — |
| export | memory ~~COLD~~ | `ExportHandler` | file destinations |
| plane | memory ~~HOT~~ | `PlaneDecl` + resumable `on_piece` + `project` | the `HostSlots` families (§11.12): clock, records (reads and one-time claims), dest, sign, unit (nested dispatch), work (work handles), trust, verify, entitlement, content scan, `hook.call`. ~~`govern_admit(expected_units)`, `route.next` / `route.settle`, journal, approval~~ SUPERSEDED 2026-09-28 by THE DESIGN §11.12: expected units ride `arrive`'s answer, routing attempts are pushed to `on_piece` as ATTEMPT pieces, record writes ride `on_piece`'s answer, and approval redemption is a one-time record claim |
| transport | memory ~~HOT~~ | `Carrier` or `Framer` | `io.*`, clock, the host auth handle at its auth points (§6) ~~, `auth.decorate` (framers)~~ |

**Dispatch.** Every call of every kind returns Ready or not-ready-with-a-wake (§11.2); a CPU-only call
returns Ready inline on the worker, and slow I/O returns not-ready and fires the wake on completion. ~~**COLD dispatch.** A
COLD plugin that declares no need and no `blocks` mark (CPU-only — ranking, memory) runs inline on the
worker. Every other COLD plugin runs on a blocking thread with a per-plugin semaphore.~~ SUPERSEDED
2026-09-27 by THE DESIGN §11.2: no blocking thread exists. ~~In debug builds a parked read on a data
worker panics.~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.11 (Q-LEAK, owner ruling R1): workers are
thread-per-core, so a call cannot simply "not exist" on one — every hook call runs on an off-worker
lane, a crossing watchdog trips at the deadline, and worker replacement (abandon the wedged worker,
spawn a fresh one into its slot) contains a call that is actually wedged, in every build, not only debug.

~~**Legacy artifacts.** A dropped-in plugin with no Statement, or an ABI below the Statement's, is read
through 1.5.5's setting classifier, limited to first-party sugar.~~ SUPERSEDED 2026-09-27 by THE DESIGN
§11.8: no legacy artifact loads.

**Each plugin tests itself.** Its `tests/conformance.rs` links it, loads its own cdylib through the
real loader, compares the two, and keeps RED arms for a wrong config, a wrong kind, a Statement
mismatch, an undeclared need and a cross-instance `ConnId`. Each kind has ONE conformance suite that
runs the shipped compiled-in build and the dropped-in build through the same table (§11.4). ~~The
loader keeps one both-ways witness per kind, on a real plugin, up to the ABI freeze.~~ SUPERSEDED
2026-09-27 by THE DESIGN §11.4: the 2026-09-27 measurement found the both-ways tests mostly compare the
Rust API against the ABI.

**One dispatcher, one opener per kind (ARCHITECT ruling 2026-09-29).** The composition root builds
ONE process `Dispatcher` at boot and holds it; `dispatcher()` is its one accessor, and the RED that
proves there is only one ships with the first kind axis. The kernel reaches a plugin of any kind only
through a contract-level `<Kind>Calls` handle, opened by that kind's `<Kind>Axis`
(`probe`/`check`/`open(module, label, settings)`) — the template is the export axis. The root
implements every axis over the one dispatcher and the plugin registry and hands them to the kernel
in ONE named struct, `RootInstall`, one named field per axis, installed through the existing
root-to-kernel door as `install_<kind>_axis`. The kernel never names the loader; in `crates/busbar`
the loader is named in one module, `root::loader`, and every other root file imports through it. A
call is submitted and awaited through the dispatcher's async completion. The memory a call lends a
plugin lives until that call completes, abandoned or not, for every kind (a submit that the watchdog
can abandon uses the lending submit). A compiled-in Rust shortcut is deleted as each sibling is
ported; a not-yet-ported dropped-in plugin keeps the retiring path only behind a marker that M6
deletes. An inbound auth verify at its `max_inflight` bound answers 503 unavailable (§11.11 R8),
decided before the verify loop runs; pending I/O is awaited, never answered 503.

**A plugin catches its own panics; nothing unwinds across the door (ARCHITECT ruling 2026-09-27).**
Every plugin builds with `panic = "unwind"` so the door macro's catch turns a panic into FAULT; a
plugin built with `panic = "abort"` is refused at build (the fleet build config and
`plugin-closure-deps` enforce it); a panic that escapes the catch aborts (§11.11 M3).

**Libraries (OWNER rulings 2026-09-28 and 2026-09-30).** A plugin may use whatever third-party
libraries it needs. The walls that remain are the design: a plugin reaches busbar only over the ABI,
its busbar closure is `busbar-contract` alone (#2/#40(a)/#84), and the host owns sockets, readiness,
TLS keys, the allow-list, pins, the breaker and money. No protocol is implemented in-tree where a
solid prebuilt library exists — HTTP/1 and HTTP/2 through `hyper` (`h2` beneath it), WebSocket through
the `tungstenite` family. ONE protocol = ONE library (TLS = `rustls`, DTLS = `dimpl`), ONE crypto
backend = `ring` (the RustCrypto crates the auth styles already carried are accepted as inherited); a
C dependency needs ARCHITECT approval; a change that adds dependencies states its `cargo tree` diff.
A plane is transport-blind: it names no transport crate and speaks only the ABI's field shapes
(ARCHITECT, 2026-09-30). A plugin holds no process-global state: what it keeps is per-instance, and what
must survive a restart goes to its records through the store kind (F15). The one owner-approved
per-thread slot is the door's log-capture slot, macro-expanded into each plugin (§11.2).

**Statement facts a boot can read without opening the image (ARCHITECT rulings 2026-09-28/29).** A
transport's claims are Statement facts: `Statement.claims` is the ONE source of the scheme names it
serves, rendered into the signed manifest's Statement section, so Select picks a dropped-in transport
from the signed manifest without opening it and the admit check's byte compare covers the claims (the
door must match). The transport tail's claim rows are metadata parallel to it by index; admit refuses
a length mismatch, and a Statement of any other kind that carries claims is refused. A framer states
an EMPTY `composes_over`: the carrier under it is the connector's choice from the target scheme, and no
transport names another. A per-need protocol field (`need.protocol`, `LocateIn.protocol`) was
WITHDRAWN 2026-09-30: a protocol that needs its own framing is its own transport (§5).

**A port keeps 1.5.5's surface (PORT R7/R8, ARCHITECT rulings 2026-09-30).** A plugin rewritten onto its
kind's ABI keeps the published 1.5.5 plugin's config keys, refusal texts and wire bytes. A key 1.5.5
read outside `settings:` for that entry stays where it is: the kernel deals the plugin its whole entry
minus the core-reserved keys, and the Statement's settings schema declares those keys (secret fields
marked secret). A guard core used to apply to the plugin's hops becomes the plugin's own logic, on top
of the need's egress class and never weaker than 1.5.5's. Any 1.5.5 behaviour difference, a fix
included, lands in its own commit and is queued for the owner; the default is 1.5.5's behaviour.

**Validation refusals, every kind (ARCHITECT ruling 2026-09-29).** A plugin's validate refusal may be
several lines. A line that starts with a `settings` path is instance-relative, and the host renders it
as `<kind-section>.<instance>.<line>`; any other line is rendered verbatim. The rule is stated once in
`abi/mechanism` with its check and a RED; the 1.5.5 refusal bytes are pinned.

**Planes — protocol scope and per-plane rulings.** Owner direction 2026-09-29: maximum compatibility —
every plane supports the transports and bindings its protocol's official design defines. Owner scope
2026-09-29: IN — MCP session-based Streamable HTTP (revisions 2025-06-18 and 2025-11-25), MCP's legacy
HTTP+SSE (2024-11-05), the Bedrock InvokeModel dialect, A2A over gRPC in both directions (inbound and
outbound, over h2 with TLS and h2c), A2A push delivery, the Twilio Media Streams
leg and WebRTC media (#45); OUT — native SIP (#45). Priority (owner 2026-09-29): mcp, a2a, llm and
decisions before streaming.
- *mcp (FOLD-MCP F25 and MCP-COMPAT, ARCHITECT rulings 2026-09-29, inside the owner's scope):* the
  baseline is current `predev` behaviour with the MCP-COMPAT exceptions; subscribe stays for the old
  revisions; the plane's `meter()` equals `predev`'s (`$`). Sessions: a CSPRNG id of at least 128
  bits from the host, bound to its owner `{principal: actor id, credential: key id | "<ungoverned>"}`
  (no tenant noun) — a mismatch answers 404 on every path; revision by negotiation only, no revision
  config; sessions are per process; the stateless path of MCP's 2026 revision stays byte-identical; per-owner session
  and byte quotas; an ungoverned chain is unisolated and says so, with a per-instance boot diagnostic
  latched on the first legacy stream. Sessionless GET+SSE: `MCP-Protocol-Version` present
  (streamable revision) → 405; absent → the legacy 2024-11-05 stream; plain GET or DELETE with no
  session → 405. Homes: the stdio supervisor is the stdio transport's; RFC 8693 exchange is the auth
  kind's `exchange()` (F7); the tools grammar is the plane's; the task store is host records.
- *a2a (A2A-PUSH, FOLD-A2A; ARCHITECT rulings 2026-09-29/30):* a claim may be a path PATTERN (a `{…}`
  segment is a variable), resolved under CG-62's precedence (§2). Push delivery retries at most three times
  (250/500 ms ±20 %) on a transport error, 5xx or 429 only, on an async timer, holding no slot, and
  re-runs the destination judge on every attempt; streaming-sink delivery is detached through a
  per-task ordered bounded queue (64, drop-oldest, counted). A gRPC binding reads `grpc-status` from
  the trailers (the 1.5.5 trailer drop applies to llm paths only).
- *decisions (OWNER rulings 2026-09-29/30, DECISIONS rulings):* like llm, N dialects over an IR — but
  the engines named so far are PROVIDERS of the one dialect (protocol `jev`, the `/v1/systemone`
  spine), as groq is a provider of the openai dialect (#51): catalog rows carrying their `error_map`
  and any #51 path override, bytes passing through (an engine that speaks the openai dialect is an llm
  catalog provider instead); a second
  dialect exists only where a provider's request spine really differs (NanoJev is the one, dialect
  `nanojev`: `/api/evaluate` is its second exact claim; a model's dialect is its override or its
  provider's protocol; a model of the wrong dialect gets that dialect's existing unknown-model refusal;
  it meters the upstream's own billing unit, counted from the answer already read (`execution.states`;
  an answer with no count refuses loudly; `$`, alone), with no extra egress; a cross-dialect request is a validate refusal unless the translation is exact). Usage
  pointers are dialect data. The binary feature `plane-decisions` is the plane's one switch. Model
  resolution: all configured decisions models are listed (scope-filtered); a request routes by its
  model; one configured model and none named is the default (byte-identical); more than one and none
  named is 400; an unknown model is 404. `upstream_model` rewrites only the top-level model value, by
  span splice, when it is set and differs; otherwise the body passes through. `/v1/models` appends each
  plane generation's listed names (bytes unchanged when none).
- *llm (BEDROCK-INVOKE, ARCHITECT ruling 2026-09-30):* a model entry may override `protocol` and
  `error_map` exactly as #51 states, fail-closed. A MODEL-ONLY protocol (`ProtocolDecl.model_only`) is
  never a valid provider default and is excluded from the must-be-one-of list; its telemetry index is
  appended after the 1.5.5 families. Bedrock InvokeModel serves Anthropic-on-Bedrock chat only (the
  other families are reachable through Converse); its usage row is `$` and lands alone.
- *streaming (OWNER ruling 2026-09-29):* exactly three dialects — OpenAI Realtime (WS and WebRTC),
  Gemini Live, Twilio. Twilio is a dialect over the ws transport (no transport crate of its own),
  claimed on a one-level `/twilio` path prefix. Tools mid-session are relayed to the client; the gateway runs no tool
  executor of its own (the echo executor is deleted) — the #45 clause on executing tools through the
  MCP plane is queued as an owner question (`1.6.0-QUESTIONS.md`) and not folded here. A session is
  keyed to its caller by the opaque caller reference (Part 3 §12), never the raw principal (a privacy
  fix against `predev`), and the plane serves its own protected-resource metadata document
  (ARCHITECT, 2026-09-30).

**The export kind** (OWNER-LOCKED 2026-09-22) turns busbar's observations into another system's
format: (1) read-only on the observation stream — if it can change what busbar does it is a hook;
(2) it owns the destination's format, core owns none; (3) its failure is never the request's problem —
off the hot path, buffered, shed under pressure; (4) money- and pricing-blind; (5) compiled-in or
dropped-in like every kind; (6) it declares its needs as (transport, auth) per direction and opens no
socket. **An exporter is not a plane:** no admit, no meter, no settle, no teller loop — the resemblance
is the carrier request and nothing else.

### 3. Boot

The owner's four phases — read config, load plugins, register, serve — in dependency order:

| Stage | Does |
|---|---|
| 0 Plan | parse the core envelope, incl. the `plugins:` policy; secret refs stay raw; rewrites run |
| 1 Discover | read manifests only and build the image set; nothing is loaded |
| 2 Select | pick the plugins config uses (§2) |
| 3a | open the bootstrap secret plugins |
| 3b | the connector registers every transport and activates the selected ones |
| 3c–3d | fetch plugins through the connector, then Discover and Select the fetched set in the same boot |
| 3e | admit every selected need; open the network secret plugins |
| 3f | inbound listener security |
| 3g | deal config sections; plugins validate; open the rest; create the auth objects (§6) |
| 4 Book | open the store, replay the WAL, seal the opening, bind the keyset — at boot only |
| 5 Seal | build the generation; build guest lists and bindings; the §6 refusals |
| 6 Serve | listeners open |

**Reload** runs stages 1–3 and 5, never Book: the store carries over, and a changed `store:` applies
on restart, as in 1.5.5. Auth objects are rebuilt per generation, so a rotated API key applies on the
next attempt. A validation refusal keeps the running generation. **`--validate`** runs stages 0–2
and the validation half of 3g, and the guest-list refusals — nothing dials and no store opens. **`--list-plugins`** runs stages
0–1. `crates/busbar/src/root/boot.rs` is the one source file that names the loader.

**Config-derived keys are leaked once** (CG-06, 2026-09-05). An id, name or other open-vocabulary
key known only from config is turned into a `&'static str` exactly once, at the registration that
reads it — never per connection, per dial, per call or per frame. A leak anywhere else is a defect.

*Proven by:* the 1.5.5 validate golden; `boot_lines_neutrality`; RED arms for one seal after two
reloads, `tools:` added on reload, and a provider key rotated on reload.

**The boot chain (BOOT-CHAIN, ARCHITECT rulings 2026-09-28/29).** Discover and Select read Statement
facts from the signed manifest, which is the no-dlopen source (the object-section reader is
withdrawn); Select is a pure function first, then flipped on behind its gate. The old HOT/COLD
boot-loop steps 4-5 are SUPERSEDED. **P1:** a plane that exports a plane-kind door loads through
`load_linked`/`load_dropped::<Plane>` (Statement + tail → the plane row). A plane that is still
HOT-only is a transitional row, drained by its own fold. **P2:** the last fold deletes the HOT read
path. Every fold's flip ships that plane's door and its linked door row.

**Inbound listeners (INBOUND-LISTEN, ARCHITECT rulings 2026-09-29/30).** Boot collects every inbound
need and its bind from the instance's settings — the 1.5.5 shape `{listen, tls{cert, key, client_ca?}}`,
secrets by reference; the connector binds ONE listener per need and, per accepted connection, runs the
framer's accept side (under the TLS server wrap when configured); the ALPN offer is the framer's.
`max_conns` defaults to 1024 (a CHANGELOG line); two needs naming one address are refused at
validation (amended 2026-09-30 by THE DESIGN §6: needs naming a configured listener share it as lines). The data and admin root listeners are in the same inbound bind list and bind through the
connector (the admin router stays separate; the root binds uncapped); `--validate` prints plugin
listeners only. The connector's listening set is the one listener source: the root's stream hand-up
is permanent for the admin listener and transitional for the data door until the plane driver serves
it. Until then boot refuses a plugin's inbound need. ONE root `Connector` serves inbound and outbound,
built once at boot (a RED holds that both sides get the same instance).

### 4. Config

Every kind is configured. The root keys fall into three classes — the 1.5.5 root shape.

**(A) Core-owned keys** — the teller loop's own settings: `listen`, `public_url`, `tls`,
`admin_listen`, `admin_tls`, `admin_require_mtls`, `config`, `auth` (`chain`, `admin_auth`,
`role_bindings`, `signing_key`, `key_ttl`), `groups`, `rate_card`, `per_request_fee`, `security`,
`limits`, `health`, `routing`, `advanced`, `plugins` (the loader policy).

**THE KIND → VERB LIST.** The kernel may know kinds, so it holds this list — one `kind: verb` line
per kind, in exactly one place in code, `Kind::verb()` beside the closed `Kind` enum
(`busbar-contract/src/plugin.rs`). Every config reader, `--validate`, `busbar migrate` and the
selection step (Law 7) reads the root keys from it; no other code spells a kind's root key.

```
store:     store
secret:    secrets
auth:      identity-providers
hook:      hooks
export:    export
transport: providers
plane:     (declared — each plane plugin declares its own verb(s) in its Statement)
```

The plane line is the one entry the kernel cannot fill, because a plane verb is instance knowledge
(`pools`, `tools`, …) and the kernel names no instance: it reads plane verbs from the loaded plane
plugins' Statements. A new kind is a kernel change; a new plane is not.

**(B) One root key per non-plane kind** — define once, reference by name. The key belongs to the
KIND, never to a plugin: no store, secret, auth, hook, export or transport plugin gets a root key of
its own. Each entry picks its plugin — by `module:`, or for transport by the URL scheme it claims.

| Root key | Kind | Shape |
|---|---|---|
| `store:` | store | one instance, `{module, settings}` — **required** |
| `secrets:` | secret | module-level open settings, keyed by module; a secret is used by reference anywhere (e.g. `{env: X}`) |
| `identity-providers:` | auth, inbound | named entries, referenced by name from `auth.chain`, `admin_auth`, `role_bindings` |
| `hooks:` | hook | named map, referenced by bare name from `pools.hooks` or a pool's `hooks:` |
| `export:` | export | named map: `module` plus a `streams` projection |
| `providers:` | transport | named map of upstream destinations; an entry's `base_url` scheme picks the transport plugin (below) |

Outbound auth has no root key of its own: its style is the provider entry's `auth:` field (§6).
Transport settings stay at their 1.5.5 paths under `limits:` (e.g. `limits.upstream_http1_only`),
declared by the transport plugin. A non-plane plugin's own connections (a store URL, a vault
address) are its settings under its kind's key, not `providers:` entries.

**(C) Plane verbs** — the plane is the only kind whose plugins bring their own root keys: llm →
`pools` and `models` (two root keys, as in 1.5.5; the llm plane owns both); mcp → `tools`; a2a →
`agents`; streaming → `streams`; decisions → `decisions`. The plane declares its verbs; the kernel
names none. The root `streams:` (the streaming plane's verb) and `export.<name>.streams:` (an export
projection) are different keys. Tool and agent pools sit under their own plane's verb as a reserved
`pools` sub-key, and `busbar migrate` moves 1.5.x pools there.

**`providers:`** is the transport kind's root key: the upstream-destination map every plane sends to — the 1.5.5 provider entry,
unchanged: `base_url` (its scheme picks the transport), `api_key` / `api_key_env`, an optional
`auth:` (`bearer` | `api-key` | `jwt-bearer` | `oauth-client-credentials`, with `token_url`, `scope`,
`subject`), `protocol`, `error_map`. The connector owns it (catalog merge, `base_url`, trust); its
`api_key`, `auth`, `token_url`, `scope` and `subject` bind the auth object (§6); its dialect fields go
to the planes that use the provider.

**Selection follows the classes (Law 7).** A plane loads iff its verb is present. A store, secret,
auth, hook or export plugin loads iff some entry under its kind's key names its `module` (or a
reference uses its sugar, e.g. `{env: X}`). A transport loads iff a configured URL (a `providers:`
entry's `base_url`, or a non-plane plugin's connection setting) uses a scheme it claims, or a configured listener names it.

- **Reserved core-owned sub-keys** are read by the kernel from any plane's section and stripped before
  the section reaches the plane: `breaker`, `on_exhausted`, `gates` / `hooks` (the hook bindings),
  `upstream_credentials`, `affinity`, `tier`, `repeatable`, `rate_card`, `fees`.
- **`store:` is required**, even for memory. Without it boot refuses and tells the operator to add
  one, e.g. `store: {module: memory}`, and to run `busbar migrate`, which inserts exactly that. This is
  a signed customer-visible change from 1.5.5.
- A plane's section is required only when that plane is linked; the default build keeps 1.5.5's error
  bytes. Sections carry position maps, so 1.5.5 line and column numbers survive rewrites.

**Pools and work bounds under the plane verbs (POOLS-VERBS, ARCHITECT ruling 2026-09-30).** Pools are
lifted into each plane's own section (#43, #47); the root `pools:` stays llm-only, as in 1.5.5; pool
names are unique across planes; a `pools` sub-key under `decisions` or `streams` is a validation
refusal; `busbar migrate` moves 1.5.x pools and prints a visible TODO report. A plane's reserved
`work: {max_live, retain_s}` sub-key is lifted the same way and joins the reserved core-owned sub-keys;
a plane entry named after any reserved key is refused at validation with a clear message (a generic
check). A plane receives, at open, the dialect fields of the providers it references and resolves
model → dialect itself; the kernel checks no dialect (ARCHITECT, 2026-09-30). A plane's settings reach it as ONE
validated JSON object `{section: value}` per `open`/`refresh`, reserved keys and secrets stripped;
`upstream_credentials` is kernel-owned (FOLD-LLM2 Q1, FOLD-A2A, 2026-09-29/30).

### 5. Connections

**Every plugin that needs an external connection declares a need, and the kernel instantiates the
transport.** One mechanism for every kind: a plane, an exporter, a store driver, vault, an IdP call
or a third party's secret plugin asks the same way and gets the same thing, and the kernel never
learns its name or kind. No plugin opens a socket, dials, binds or does TLS. A need is `(direction,
transport, auth, target_from, trust_from, egress_class)`. It asks for a raw byte stream (a database
wire protocol, framed by the plugin itself) or a framed transport (http).

**The chain is kernel → `busbar-core-connector` → transport plugins.** The kernel knows nothing about
transport. Transport plugins have two roles: **carriers** (`tcp`, `stdio`) dial, accept, read
and write; **framers** (`http`, `ws`) are sans-IO state machines. One plugin is one entry, and the
schemes it serves are its claims — http claims `http`, `https` and `sse` ~~and `grpc`~~ (SUPERSEDED
2026-09-29 by OWNER ruling: gRPC is its own transport, below); ws claims `ws` and
`wss`. Two plugins claiming one scheme refuses boot, and no transport names another. The connector
builds every connection as **carrier → [TLS] → framer**. TLS is core-only, inside the connector, and
is never a plugin. The http framer drives hyper over an in-memory pipe, so the wire bytes are
hyper's, h2 included.

**The host table** is the same for every kind: `conn.open(need, {target, fields, body, timeout}) →
ConnId`, then `write`, `read`, `wait`, `facts`, `close`. A `ConnId` belongs to the plugin instance
that opened it; every operation checks that, and a cross-instance id is refused.

**Delivery.** Every kind is on the memory ABI (§11.1). Planes and transports are pushed their bytes:
a plane's resumable `on_piece(state, request, piece, reply_buffer)` runs on the owning worker and
returns its running unit report with its answer, so a plane makes zero calls back into the host per
chunk. A plugin of any kind whose I/O is slow returns not-ready and fires the wake on completion; no plugin thread
exists, no blocking thread exists, and no host pointer outlives a call. ~~COLD plugins pull: the call
parks on the connector's cold-I/O runtime~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.2. Transports get
readiness through `io.{register, poll_ready, clear_ready,
deregister}` on the per-worker reactor.

**Egress classes.** Targets come from operator settings; first-party means a grant in the root manifest. Every declared need is held to its configured target (PB-100, ARCHITECT 2026-09-30): the loader's connection-table fill resolves a need's `target_from` against the instance's validated settings at open and refresh and declares the need pinned to that target; a `target_from` that resolves to nothing refuses that need, a refresh that changes the value re-declares it, and a dial to any other host is refused.

| Class | Used by | Rule |
|---|---|---|
| `provider` | plane upstreams | allow-list + `allow_metadata_hosts` |
| `operator-infrastructure` | databases, vault, ldap | private, loopback and plaintext allowed; pinned; cloud metadata hosts refused (accepted difference, owner 2026-09-27) |
| `open-web` | webhook; auth mint endpoints (`token_url`, `token_uri`) | public https only |
| `loopback-allowed` | otlp, webrequest | https, or loopback plaintext; the node's own ports refused |

**`/metrics` is not in core.** `/metrics` and `/metrics/hooks` are listener needs of the prometheus
export plugin, fed by a kind-neutral snapshot service. The path, the 503 boot window, the
first-party gate, the content-type and the series stay 1.5.5 bytes.

**Drivers.** postgres runs over `connect_raw`; valkey over synchronous `redis` `ConnectionLike`
~~on the blocking pull adapter~~ (SUPERSEDED 2026-09-27 by THE DESIGN §11.2: the store call returns
not-ready and fires the wake on completion, never on a blocking thread; the store kind ABI fixes how) (no `aio`); vault, oidc, github, webrequest, webhook and otlp through a one-shot
`exchange()`. webrequest's upstream bytes stay identical to 1.5.5.

**One outbound request, kernel to wire.** http and https differ only in the steps marked *https only*.

| # | Who | What happens |
|---|---|---|
| 1 | KERNEL | route (pool walk, member, breaker), allow-list + pin, budget; pushes the chosen attempt to the plane as an ATTEMPT piece (Part 3 §12) |
| 2 | PLANE plugin | answers the ATTEMPT piece with the unauthenticated request (verb, target, dialect headers, body) ~~builds the unauthenticated request and calls send(to: provider X)~~ SUPERSEDED 2026-09-28 by THE DESIGN §11.12 |
| 3 | CONNECTOR (core) | gets a conn: the tcp CARRIER plugin dials; *https only:* the TLS wrapper handshakes (connector, core); the http FRAMER plugin sits on top |
| 4 | FRAMER | finalises the head |
| 5 | FRAMER → auth handle → AUTH PLUGIN | at the framer's bound auth points (§6, "Auth points and guest lists"), the one per-request call through the host auth handle returns the auth fields, which join the head (§6) ~~`decorate(final head)` → the credential header~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.6 |
| 6 | FRAMER | encodes (hyper) |
| 7 | CONNECTOR | *https only:* TLS encrypts |
| 8 | CARRIER | writes (readiness via core `io.*`) → wire |

The return path runs in reverse; the plane reports the units it did, and the kernel meters them (§7).

**Who sees what.**

| Party | Sees | Never sees |
|---|---|---|
| plane | the content | the key; the socket |
| kernel | provider name, destination, units, money | what the content means |
| connector | everything below the framer, TLS and DTLS keys included | — |
| auth object | the API key | — |
| http framer | the finished headers, the key included, in transit | TLS keys |
| webrtc framer | the SRTP keying material the connector's DTLS engine exported (it protects media, as http sees the headers it frames); plaintext SCTP | DTLS keys, the session certificate's private key, the DTLS state |
| carrier | ciphertext on https | — |

*Proven by:* a secret-kind test plugin that dials through the connector; kernel × transport = 0;
2,000 concurrent streams (`cap.perf.streams-2000`) — every stream completes, no speed threshold; zero
plane→host calls per chunk. ~~a same-machine A/B against published 1.5.5 on the llm path — p50 ≤ +5 %,
p99 ≤ +10 %, req/s ≥ −5 %~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.9: the A/B against published 1.5.5
is the PERF phase's (after DEV-GREEN), on the fixed reference machine.

**The host connector — one design (ARCHITECT rulings 2026-09-27/28 and 2026-09-30).** One connector
serves every kind that needs a connection, through ONE `Need` shape that every kind's Statement and
tail may carry: direction, egress class (one of the four above), `target_from`, `trust_from` (an extra
trusted root added on top of the public roots, as in 1.5.5) and auth; the loader fills each instance's
connection table for the needs it declared. A need asks for a raw byte stream or a framed one
(http); `exchange()` is the SDK's one-shot helper over a FRAMED http need — one request `{method,
target, fields, body, timeout}`, not-ready until `{status, fields, body}` under the caller's cap — so
its bytes are hyper's. The 2026-09-28 rulings that put the endpoint list, its ordering and the pool
in the host are SUPERSEDED 2026-09-30 by ARCHITECT ruling (PORT R4): **a
database or directory wire protocol is plugin logic over the generic connection table, and needs no
new host shape** — the plugin tries a multi-host endpoint list in order (open; on reject close and try
the next), runs the startup and authentication handshake (SCRAM, md5, AUTH/SELECT, bind) over the raw
stream, keeps its per-instance pool as its own set of `ConnId`s held across not-ready turns with
reset-on-return in plugin code, and cancels over a second connection on the same need; a driver is a
sans-IO codec over the host stream, never a blocking driver (the `mysql-ldap-stream` ruling, §10).
Streams are full-duplex (the plugin may write while a read is pending), and a full-duplex connection
holds TWO tickets, one per side, each with at most one op in flight. TLS is `upgrade_secure` on the
connection — ONE generic mid-stream service owned by the connector — after which the connector exposes
the server certificate hash (channel binding). A store op holds ONE checked-out connection across its
not-ready turns, released on READY, FAILED or cancel; a write-behind op keeps its connection across a
reload. The host supplies randomness and the process identity at open; statement naming is the
plugin's; server notices become #85 diagnostics. Deadlines are host-owned, per read. A local-disk
store opens its own file and answers Ready; the host runs its calls on the bounded disk lane (§11.11
R4), and a host service that reaches such a store offloads onto that lane and answers FAILED if it
fails (ARCHITECT, 2026-09-29/30). The connection table reaches a plugin only through its
`open`/`refresh` host tables and lives in its instance state (`busbar-contract` holds no static; "no
table handed" is `ConnError::Unarmed`, per instance). The connector's internal wire surface is its own
trait, never the plugin transport face; the legacy transport face is adapted in the composition root
as a transitional row deleted at step 36.

**Dialing only what the kernel judged (CONNECTOR-19, ARCHITECT rulings 2026-09-29).** The connector
dials IP literals the kernel has judged: a `DialJudge` trait (no connector-to-kernel edge) that the
kernel implements with its ONE destination judge; the connector dials exactly the pinned judged
address, name resolution pends inside a ticketed op, and the 1.5.5 refusal timing holds. A dial is
judged under the need's own egress class. No path may regress from "hostname refused" to "hostname
dialed". Writes are back-pressured (a full buffer answers not-ready); an mTLS identity that fails to
parse is a boot refusal. The cloud-metadata refusal (§10, `cloud-metadata`) is a pure check in the
connector's endpoint check, run before any dial, over the whole 169.254.0.0/16 link-local range,
`fd00:ec2::254`, `fd00:ec2::23`, `100.100.100.200`, `192.0.0.192` and `metadata.google.internal`, in
every spelling (IPv4-mapped, decimal, octal) (ARCHITECT ruling 2026-09-28).

**One secure layer, sibling engines (OWNER ruling 2026-09-30).** The connector composes **carrier →
[secure layer] → framer**; the secure layer is ONE core-owned slot with sibling engines — `tls`
(stream, `rustls`, today's code moved byte-identically) and `dtls` (datagram, `dimpl` on `ring`). The
host owns every key; a framer gets plaintext and, where it needs one, the keying-material exporter
through one generic ABI item.

**HTTP and gRPC framing (OWNER rulings 2026-09-28/29; GRPC-DOOR rulings 2026-09-29/30).** h1/h2
framing lives in the http transport plugin, built on `hyper`'s client/server connection API over the
host-socket shim — readiness from the host's `io.*`, not-ready answered through the ABI wake, a
per-connection executor inside the plugin, the timer on the host clock through `tick`. Parity with
1.5.5: ALPN h2 by default to providers, the h2c prior-knowledge key, the http1-only key, keep-alive
30 s / 10 s, the adaptive window; h1 port normalisation and the h2 HPACK and SETTINGS-ack bytes match
1.5.5's (the recorded step-20 wire cells). The ws door marks a text frame with a vocabulary bit, no
layout change. When the caller sets none, the http door adds `accept: */*`, and on
h1 the host header and origin-form target: the http transport owns the client defaults (owner-agreed
2026-09-28). **gRPC is its own transport**, `busbar-transport-grpc` (OWNER 2026-09-29: *"1 new transport
and thats basically it"*): a framer over the carrier running hyper's h2 client and server itself;
the connector composes ONE framer per connection, and no framer stacks on another. Its acceptance is
the owner's claim: outside its own crate the change is a root row, the workspace and pre-tag vocabulary
only — zero kernel or plane change. gRPC ingress is a dedicated listener. The code the framers share
is `busbar_contract::hyper_io!`, a `macro_rules!` in the contract's SDK area expanded in each framer
against that framer's own `hyper`/`bytes` dependencies; the contract gains only dev-dependencies. A
shared transport "kit" crate is refused (it breaches #40(a)'s contract-only closure and creates a
transport-to-transport edge), and so is a trailer piece on the transport ABI. The legacy in-process
gRPC transport and the kernel's shared-port gRPC service are deleted right after the door lands, with
the supported path proven end to end before and after.

**The response head and trailers (HEAD-FIELDS, K2, GRPC-DOOR; ARCHITECT rulings 2026-09-29/30).** A
framer yields the response head as the FIRST `Fields` piece, always — an empty one carrying the
status when there are no headers; a `Fields` piece after the body is the trailers; `Fields` with
`STREAM_FAILED` is refused. The head reaches a plane only on the far-end path (the far piece's head
and the `on_piece` field list): each plane DECLARES `keep_response_headers` at boot — at most 32,
lowercase, never a hop-by-hop or credential name, validated — and the kernel copies only those. For
gRPC the head carries no status code; the trailers carry `grpc-status`, then a terminal piece (empty
on OK, `STREAM_FAILED` with `grpc-message`), bytes as 1.5.5. On the accept side a framer yields a
typed per-stream head (`HeadSlots`, Part 4 Axis 3) with the first `Fields` piece, and the kernel
fills `arrive`'s method and target from it: request pseudo-headers travel in typed head slots, never
as fields, and a pseudo-field inside `Fields` is refused. `te` is checked at the door as 1.5.5 did — a
missing `te` is served, a wrong one is reset with h2 `PROTOCOL_ERROR` — then dropped as hop-by-hop. A
transport's emit carries the response status as a typed `u16`, never a magic `:status` header, with
its validator wired and a RED in the first commit that sets it.

**Datagram media (WEBRTC, ARCHITECT rulings 2026-09-30).** WebRTC mirrors HTTPS layering: the udp
carrier is the host's (in the connector, no carrier plugin); DTLS runs in the connector's secure layer
with the host certificate, RFC 7983 demultiplexing, cookies and ICE-gated associations; the webrtc
framer holds ICE, SRTP and SCTP and gets the exported SRTP keys through the keying-material item — it
holds no DTLS state. SRTP is AEAD-AES-GCM only (`AES_CM` refused); the `aes`/`cipher`/`inout` crates
are the one exception to `ring`-only, confined to the SRTP key derivation by a dependency-closure
test. ICE path migration rebinds only on a verified round-trip check (a spoof is a RED); keys are
zeroised; application data waits for peer verification. Opus passes through; no C codec (`libopus`
refused). Admission is at SDP accept (`$`). Tickets are busbar-minted.

### 6. Auth — one vocabulary, per-generation bindings and guest lists (OWNER-LOCKED 2026-09-27, 2026-09-30)

~~**The rule.** Auth is on the memory ABI (§11). For every request the kernel makes ONE uniform call to
the provider's auth plugin: *give me the auth fields for this request*. Each auth plugin caches inside
itself; the kernel holds no auth cache and does no per-plugin branching. The kernel knows only "auth
plugins", and it routes each call by the style the provider entry resolves to. The crossing measures
~42 ns — owner: noise. The call never blocks.~~ SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points
and guest lists".

1. **The plane sends an unauthenticated request.** The kernel's route walk picks the attempt and
   pushes it to the plane's `on_piece` as an ATTEMPT piece; the plane answers with the verb, the target,
   the dialect headers and the body, bound for the far end. It never sees a key. ~~It asks `route.next`
   for an attempt and writes the method, path, dialect headers and body.~~ SUPERSEDED 2026-09-28 by
   THE DESIGN §11.12: `route.next` and `route.settle` are not host services; the walk drives, the
   plane answers (Part 3 §12).
2. **The kernel resolves the provider when it seals the generation.** Transport = the claim for the
   `base_url` scheme. Style = the provider's `auth:`, else the plane's dialect default (bearer,
   x-goog-api-key, SigV4). Credential = `api_key` / `api_key_env`. All three are opaque strings to the
   kernel.
3. **The kernel opens the auth object:** the auth plugin that serves that style `open`s a binding to
   the resolved credential and returns a handle; the plugin keeps the binding and its cache, the kernel
   keeps only the handle. It belongs to the need and is `refresh`ed every generation.
4. ~~**One call per request.** Once per attempt the kernel calls the provider's auth plugin with the
   handle and the request's fixed fields, and the plugin returns the auth fields, which join the head
   before the framer encodes it; TLS sends it. It is the same call for every style, never per chunk.~~
   SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists".
   ~~**The transport asks it to decorate.** The connector carries the object on the conn. When the http
   framer's head is final — exactly as hyper will send it — the framer calls `auth.decorate(object,
   final head, body hash)`; the auth plugin returns the header; hyper encodes it; TLS sends it. The
   body hash is computed only for a style that needs it (SigV4).~~ SUPERSEDED 2026-09-27 by THE DESIGN
   §11.6: the framer no longer calls a `decorate` crossing; the kernel makes the one call. The framer
   now calls its bound auth through the host auth handle at its auth points (SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists").
5. **Each style caches inside its plugin.** bearer and api-key build the header once, at `open`.
   jwt-bearer and oauth-client-credentials mint through the plugin's own `open-web` need and refresh
   ahead of expiry in the background on `tick`; the plugin holds the service-account file or client
   secret, validates it, and renders 1.5.5's refusal texts. SigV4 signs per request with a daily
   signing key derived ahead of time. caller-credential passes the caller's credential through. The
   call opens no connection and never blocks: when the cached token has expired and the refresh has
   failed, it returns not-ready, bounded by the attempt's deadline — 1.5.5's behaviour. ~~`decorate` never
   opens a connection and never blocks — the host refuses conn operations inside it — so it runs inline
   on the worker, once per attempt, never per chunk. When the cached token has expired, the attempt
   waits for the refresh, bounded by its deadline.~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.6.
6. **Caller credentials.** A plane never sees the caller's credential: ~~the host strips every header an
   auth plugin reads as a credential~~ (SUPERSEDED 2026-09-30 by "Auth points and guest lists" below: the auth names its
   credential lines and query keys and the transport strips both; for inbound requests, no kernel step names an inbound credential line; the line's style names them). `upstream_credentials: passthrough` is the style
   `caller-credential`, whose per-request call receives the caller's verified credential.
7. **IdP logins** (oidc, github) hold their own client secret and make their token exchange through
   their own need.

~~The outbound styles `bearer`, `api-key`, `x-goog-api-key`, `sigv4`, `jwt-bearer`,
`oauth-client-credentials` and `caller-credential` live in one plugin, `busbar-auth-outbound`, loaded
when some provider uses one of them.~~ SUPERSEDED 2026-09-29 by OWNER correction: *"there is no
outbound auth plugin. there is an auth plugin that applies auth to connections/transports. the
direction is irrelevant."* An auth plugin serves styles; which crate carries which style is queued
for the owner (`1.6.0-QUESTIONS.md`). `caller-credential` is a credential SOURCE, not a mechanism:
each mechanism plugin serves its styles in operator or caller mode, declared by a style flag, and the
kernel maps `caller-credential {as: X}` and `upstream_credentials: passthrough` to style X in caller
mode (ARCHITECT ruling 2026-09-29). Styles are loaded when some provider uses one of them. No config changes, and the wire bytes match 1.5.5, h2 included.

**Trust boundary.** The plane never sees the key. The auth plugin holds it. The framer sees it pass.
Both are operator-trusted — signed, and granted in the root manifest; the operator chose them. TLS
keys never leave the connector. **For secrets generally,** the kernel resolves and audits secret
material and delivers it only to the auth object bound to it and to the non-plane plugin whose
settings reference it (a store URL, vault's token, a webhook header), as in 1.5.5. A plane never
receives secret bytes. Logs, audit records and metrics carry a secret's reference, never its value
(#54: *"Secret ID yes, not THE secret"*).

*Proven by:* the AWS SigV4 published vector with a session token; an RFC 7523 JWT byte-identical to
1.5.5's; an h2 bearer request byte-compared with 1.5.5; captured passthrough; a RED plane that echoes
its whole request and response and never sees the credential; the auth kind's conformance suite,
compiled-in and dropped-in builds through the same table (§11.4); the crossing under 1 µs (§11.9).
~~`decorate` p99 < 20 µs.~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.6: the JSON `decorate` crossing and
its bench are gone.

**Inbound verify (ARCHITECT rulings 2026-09-29/30).** The kernel refuses a request every inbound auth
plugin abstained on: all-abstain is 401. **Replay refusal is kernel-side:** a verified identity may
carry a `replay_key` and `replay_ttl_secs`, and the verify caller claims the record
(`auth-replay`, plugin/key, ttl) through `records.claim` (§11.12) — already TAKEN is 401. An auth
plugin that needs the request body declares the fact (SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists": that plugin's style needs `HeadBody`) and receives the body, bounded (over the bound is
a refusal). Webhook signatures are verified by ONE mechanism-named inbound auth plugin,
`busbar-auth-webhook-signature` (scheme `webhook-signature`; variants Twilio — HMAC-SHA1
`X-Twilio-Signature` — and Standard Webhooks); a missing signature is 401 end to end; a Standard
Webhooks `webhook-id` replay is refused through the claim record; Twilio carries no replay rule (1.5.5
had none, and Twilio sends no nonce). The kernel's admin authenticate step is async — it awaits a
pending verify, never answers 503 for pending I/O; a synchronous probe (`verify_now`) is ticketless
and watchdog-bounded. An auth plugin's `LoginOutcome` distinguishes an outage from a bad credential;
its service credential is a secret reference; its inbound SigV4 reads through a host store service.
The verify cache's flush count is reported as a fixed metric on `refresh`'s #85 envelope, and the
kernel sums it into the 1.5.5 `{flushed: N}` bytes. Short buffers default to 16 KiB, 256 groups and
16 fields; hard maxima are 64 fields and 65,536 groups (ARCHITECT, 2026-09-27). An IdP login plugin
uses the SDK's login kit — `begin_login` returns the authorize URL, `complete_login` answers
not-ready, an identity, a bad credential or an outage — and holds its own client secret. JWKS
fetching is sans-IO single-flight: a cold key id pends verify, one `exchange()` fetches, every waiter
wakes; `tick` refreshes ahead of the TTL, with 1.5.5's timings. The auth reply may carry generic query
parameters, and an outbound style may name a query key (ARCHITECT, 2026-09-30). The kernel judges a
token URL by the 1.5.5 rule; no plugin-set "sensitive" flag exists — 1.5.5 bytes win (AUTH-OUT,
2026-09-28). The owner signed three LDAP differences from 1.5.5 (2026-09-28), each registered when the
LDAP plugin lands: fail closed instead of panicking on a malformed reply or a hostless URL; fail fast
on an overrunning nested length; a 16 MiB inbound cap.

**The per-request auth call on the route walk (K2, ARCHITECT rulings 2026-09-29/30).** The seal-time
half of step 21 (the auth object's open and fields, the per-generation member route table) is the
walk's; waiting for auth fields is bounded by the attempt's deadline; auth material is zeroised; SigV4
signs the real method and query of the walked request; the switch-over deletes the kernel's own
outbound-auth copies in the same train, so two implementations never ship together. No SigV4 crypto
lives in the contract.

**Auth points and guest lists — how any transport applies any auth (OWNER-LOCKED 2026-09-30).** The
picture: the kernel is a valet; the connector's listeners are its driveways; each transport is the
interpreter that gets people in and out of cars; each plane's claim is a line on a driveway's guest
list, naming the auth its guests must pass.

1. **Auth points — the one vocabulary between transports and auths.** A transport never names an auth
   and an auth never names a transport (Law 1). They meet on one locked vocabulary, defined once in
   `busbar-contract/src/abi/auth` (to build; `abi/transport` refers to it). Only the owner and the
   ARCHITECT add a point, and a new point changes the auth and transport kind ABIs.

   | AuthPoint | the transport calls | the auth sees |
   |---|---|---|
   | `Head` | once per request, when the head is final | method, target, authority, field lines |
   | `HeadBody` | once per request, with the whole body held (bounded) | the head and the body |
   | `Peer` | once per connection, at connect or spawn | peer facts (the TLS peer certificate from the connector, a spawn environment) |
   | `Frame` | reserved: named, not built until a style needs it | — |

   Points are ordered `Peer` < `Head` < `HeadBody`; `HeadBody` includes the head, so a set never holds
   both.

   A transport declares the points it offers; an auth style declares the points it needs.
2. **Driveways are the kernel's.** The connector owns every listener, from
   config: each is an address bound to one transport (e.g. http; TLS is the listener's `tls:`). A
   transport never opens a port.
3. **The kernel writes the guest lists.** One per listener. A line is route → (claimant, dialect,
   auth). A claimant is a plane, a plugin's inbound need, or a cleanliness crate's route (admin,
   oauth2), registered by capability key (#26). A plane's claims go on the data listeners (`listen`);
   the admin crate's lines go on `admin_listen`, or on the data listener under the `/api` prefix when
   there is no `admin_listen`, as in 1.5.5. A line's auth may be `none` (e.g. `/healthz`), and a
   claimant may run the chain itself (the token-exchange path). An inbound need is a claim: it becomes
   a line on the listener its bind names, and brings its own listener only when that bind names an
   address no configured listener holds. The dialect on a line is an opaque id to the kernel.

   Each plane declares its claims per dialect: route, transport, default inbound auth style and
   `refusal_dialect`. A route is (method set, path — exact, `{…}` pattern or prefix — and optional
   field-presence predicates). The match vocabulary is defined once in `abi/transport`. Lines are
   ordered by CG-62 precedence (§2), a line with predicates ranking above one without, and a plane's
   lines reproduce its 1.5.5 dispatch ladder exactly.

   The auth on a line: with 1.5.5 config the operator's `auth.chain` (with `keys` where named) is the
   auth of every data-listener line and `admin_auth` of every admin line; an empty chain is `none`. No
   new config key exists. A dialect's default inbound style applies only where the operator's config
   gives a line no auth. A line's style names where its credentials sit and which lines are
   credentials; core's `keys` verifies the credential that style yields, through the same handle, and
   names no line itself.

   A line's auths are tried in order behind the one handle, by 1.5.5's chain rule: the first IDENTITY
   admits, a REJECT refuses, and all-PASS on a non-empty list is 401. The line's point set is the union
   of its auths' sets. At each point the kernel calls, in list order, each undecided auth that needs
   it, and fixes the verdict in list order at the line's last point. Every auth called names its
   credential lines whatever its verdict, and the transport strips the union. What the transport
   receives is only continue or stop, plus the lines to strip; the identity goes to the kernel only.

   A line may name an upgrade: the listener's transport runs the line's auth at `Head` on the upgrade
   request, the kernel checks the line, and the connector hands the connection to the line's transport
   — one framer at a time, never stacked. Any other claim whose transport differs from its listener's
   needs its own listener (as gRPC does, §5).

   Boot refuses: two claims at equal precedence on one listener (CG-62); a claim whose auth needs a
   point the listener's transport does not offer; a listener where some lines need `Peer` and others do
   not. `tls.client_ca` and `admin_require_mtls` are the connector's handshake gate (1.5.5), not a
   `Peer` auth.
4. **Inbound.** The listener's transport decodes the head into a neutral request (method, target,
   authority, field lines), matches the route on its guest list, and calls that line's auth at its
   points; it holds the body only when the line's auth needs `HeadBody`. `HeadBody`'s bound is the size
   gate's limit; over it is 413, answered before the verdict, as 1.5.5 did for inbound SigV4
   (oracle-checked). The handle answers the transport continue
   or stop and names its credential lines and query keys; the transport strips both, so the plane never
   sees a credential; no kernel step names an inbound credential line; the line's style names them.
   The verdict goes to the kernel first-hand, never through the transport. The verify answer carries
   the credential to the kernel as a SECRET blob, never through the transport; the kernel holds it on
   the unit, zeroised at exit, for the `caller-credential` style (§6.6). The kernel mints the unit when
   the transport makes the request's first handle call (or hands it in, for a `none` line), before any
   verdict. A 401 is a refused unit: audited, billing nothing, drawing no lease. A request that matches
   no line has no unit; the kernel refuses it with the listener's 1.5.5 no-route bytes.
   The transport hands the request in with the line it matched. Before any plane receives it the
   kernel checks, and refuses on any failure: (a) the line is on that listener's list and is the line
   the list's own match gives for the request's method, target and matched fields; (b) unless the
   line's auth is `none`, the kernel holds a verdict for this unit that came first-hand from that
   line's auth, through the handle bound to that line — a line with auth and no verdict is refused
   (fail closed); (c) none of the credential lines or query keys the auth named — which reached the
   kernel in the auth's answer — is still present. A handle is owner-scoped (#65): a transport may
   call only the handles of its own listener's lines or its own binding. A line admits anonymously
   only when its auth is `none`. A transport is trusted to show the auth and the kernel the same
   bytes; (a)–(c) catch a faulty transport, not a hostile one (§6 trust boundary). The kernel owns and
   audits every refusal; the bytes come from the line's claimant through `refusal` under the line's
   `refusal_dialect` (Part 3 §12), or, with no line, from the listener's 1.5.5 default. WebRTC media
   associations exist only for units admitted at SDP accept.
5. **Outbound.** Each outbound need (a plane's binding to a destination) gets its own binding (a
   transport context holding that binding's auth handle and pool) on the transport's instance. The
   transport finalises the head (its own lines: host, length, framing), calls
   the auth at its points, adds the lines the auth returns — replacing any plane line of the same
   name — and encodes. Nothing is added to the head after the auth has run, so what a signing style
   signed is what is sent. A binding whose auth uses `Peer` has its own connection pool. Outbound,
   `Peer` never carries TLS key material; mTLS client identity stays the connector's (§8).
6. **Tickets bring replies home.** Every request handed to the kernel carries its unit; the plane
   replies to the kernel with it, and the kernel hands the reply to the transport, which knows the
   unit's connection and stream.
7. **Handles, pending, several points.** The auth is a host handle: the kernel makes every call
   (§11.6) and no plugin calls another (Law 2). A pending answer parks only its own stream; the
   connection's other streams keep flowing. Each call carries the connection and the unit, so an auth
   that needs several points can correlate them; an earlier point may refuse. For `{Peer, Head}`,
   `Head` decides each unit; a `{Peer}`-only verdict is the connection's, applied to every unit on it;
   a `Peer` refusal closes the connection with no response bytes and is audited per connection.
8. **Generations.** Guest lists and bindings belong to a generation. A reload builds and checks new
   lists, swaps them in atomically — requests already inside finish on the old ones — and is refused,
   leaving the running generation serving, if any check fails. 'Inside' is per unit: a new request or
   stream on an existing connection matches the new lists; a connection's `Peer` verdict is re-run
   under the new generation's auth on its next unit; a session keeps its generation's handles until
   it ends; a listener set change applies on restart (1.5.5).
9. **Placement stays in the auth style** (step 2 above). What a customer sees on the wire is each
   style's own contract, proven by its conformance tests and the oracle, not by this design.

### 7. Money

- **The plane reports; the kernel writes.** The plane reports the units it did — and whether a fee
  unit was incurred — as they happen, streaming or not. The kernel writes exactly what it is told:
  one sealed line per unit, at its end; a session writes one line. Running reports are crash-safe
  checkpoints, never ledger lines. The kernel adds no floor and does no plane-specific math: a plane
  that under-reports is that plugin's bug, and choosing it is the operator's call. A line written late
  files under the window of the unit's arrival instant, never a clock read at drain time: a body that
  drains past a window edge lands in the window that admitted it — *"same balance, same window, same
  row"* (2026-09-06).
- **Spend = ledger × rate card, at read time.** No price is stored. A plane declares its classes and
  its route cost; the kernel prices generically by `(principal, meter_class, lane)`. A card that leaves
  a declared class unpriced refuses boot. `cheapest` = Σ price × the plane's declared weight over the
  card in force. The operator surface names no figure of its own: an admin view that shows money reads
  it through the ledger's read-time view types (owner, 2026-09-08).
- **Budgets.** `admission: exact` (the default) refuses at admit only a budget already exhausted.
  `admission: estimate` is one check at admit — the plane's expected units × the highest price among
  the allowed destinations, against what is left — a guess by design, kept simple for the kernel; the
  route walk never looks at the budget. `on_exhaustion: finish-unit` (the default) finishes the unit in
  flight; `cut-stream` cuts it, and a cut bills what streamed. A non-streaming unit overshoots by at
  most one request. The budget check may use the plane's estimated units; billing never does: a
  line carries only far-end-reported units (`UNITS_REPORTED`), and "what streamed" is the last
  far-end-reported cumulative count the plane gave before the cut (owner, 2026-09-28). This is 1.5.5's
  rule, measured against the v1.5.5 source: 1.5.5 had no budget cut of a stream at all (its
  exhaustion behaviours were `block` and `downgrade`, `crates/busbar/src/config/groups.rs:183`); a
  stream cut mid-flight by the far end set `stream_failed` (`crates/busbar/src/proxy/response_body.rs:283`)
  and the drop-time billing gate then billed no tokens (`:642`); a stream the caller left billed only
  the usage the far end had reported so far, and zero when no usage frame had arrived (`:633`-`:660`;
  the billing source is the terminal usage the far end reported, `crates/busbar/src/proto/stream.rs:881`).
  In both cases the request unit still counts: the `route.failover|fo|primary-cut-stream` cell's 1.5.5
  golden is usage `{"requests":1}`, tokens 0. That cell and every `billing`, `ledger` and `teller` cell
  stay byte-identical to 1.5.5; a budget cut of a stream is new 1.6.0 surface.
- **A cut is told to the client and booked as what happened.** Client side (owner, on or before
  2026-09-15): *"A cut IS a reason the client is told. Where the protocol carries a place to say so, a
  cut ends the stream WITH AN ERROR FRAME naming budget exhaustion — not a silent end of stream."* A
  silent end would make a cut look like a short answer. Ledger side (#77(7), 2026-09-20): a cut is not
  a refusal (#62); it settles one closed Abort line carrying the class, the cap and the delivered
  quantity.
- **A session is one unit with one line (owner, 2026-09-28).** The kernel owns session money. A
  duplex session admits at its open; each turn's cumulative units become a kernel session-account
  CHECKPOINT — crash-safe, on a bounded cadence and a named store slot, never a ledger line and never a
  durable write per piece; a checkpoint that dries the budget cuts the session; the session's end
  writes ONE sealed line. The plane reports counts only and holds no reservation. The retired
  per-turn ledger write of the old session meter is not reused. This strikes #28's session seam (3)
  ("the plane keeps its plane-side reserve + per-turn/per-frame settle").
- **A refusal names no amount.** A refused request of a plane new in 1.6.0 (mcp included) is
  unpriced, and its refusal names no amount or budget (owner, 2026-09-12; scoped 2026-09-27). The llm
  plane's refusal bytes stay 1.5.5's.
- Auth objects touch no money.

- **Attribution (F14, ARCHITECT 2026-09-28).** The kernel bills the unit's principal. A plane's own
  ids (agent, context, task) live in that plane's records and are never kernel nouns.
- **Cancel billing (F13).** Money follows 1.5.5's four cancel rules; where a cancel disposition would
  bill differently, the disposition must express the 1.5.5 outcome — never a silent change. A cancel
  disposition is `UNKNOWN`, `NOT_APPLIED` or `APPLIED`; the dispatcher carries it to the caller and a
  FAULT on cancel is FAULT (ARCHITECT, 2026-09-27). A flat-fee cancel refund is 1.5.5's, cited; an end
  posts exactly once; accruals use checked addition and a duplicate class is refused (K2-5,
  2026-09-30).
- **The money chain (MONEY-CHAIN, ARCHITECT ruling 2026-09-30).** A change to how many ledger rows a
  unit writes must keep every 1.5.5 oracle cell identical, or it stops. The budget mode keys on the
  budget limit; downgrade (at admission) and cut-stream (mid-stream) coexist; a checkpoint is a
  durability `unit.accrued` record; an Abort line carries the CUT posting flag. The integrity
  verifiers are wired into the 1.6.0 `GET /api/v1/admin/verify` surface — the real checkpoint anchor,
  the boot recheck's findings, the audit chain verified over retained records (#82), the amend
  journal, and the resume-break drain — with no change to a 1.5.5 byte; `GET /audit` is unchanged.
- **A tampered record is never a torn tail (MONEY-CHAIN, ARCHITECT ruling 2026-09-30).** A WAL record
  is framed with its length and a header checksum; only a true torn tail is truncated; a complete
  record that fails its body check is quarantined and reported in the restart findings, and a unit
  named by a quarantined record is never settled at 0. (The defect: a tampered complete tail record
  was truncated as torn, and a billed settlement became 0 with no alarm.) `$`, alone.
- **One audit record per unit (U14, ARCHITECT ruling 2026-09-30).** The audit record is sealed at the
  unit's one line, from the facts the audit step kept on the unit; its recipe v4 is v3 plus the boot
  incarnation; the journal carries the v4 body; the in-memory ring of 1024 is only a cache, and an
  older `/audit/range` decodes from the journal; a refused unit gets a record too (outcome refused,
  its step, an empty amount). Non-`$`, proven with the money proof.
- **Every reported class is registered (ARCHITECT ruling 2026-09-30).** Every usage class is declared
  by a plane or configured by the operator at boot and registered once; a plane declares every class
  it reports (a test holds declared ⊇ reported); the one line resolves reported classes through the
  registration, and a class that does not resolve is a plane fault — refused fail-closed with a
  finding, never dropped, never free text, never 0. With no card, rows still count at 0, as in 1.5.5.
  The audit step's pass travels with its facts to the one line, which consumes it to seal; nothing
  mints an audit pass freely. The audit digest that ships is v4 (v3 never shipped).
- **Unit keys and op ids (WIRE-STORE Q10, ARCHITECT ruling 2026-09-30).** ONE node allocator in the
  kernel mints every unit key and every store `OpId`: the node half is a per-process, non-zero u64
  from the OS CSPRNG, the counter a process-wide atomic from 1 (`OpId` = node ‖ counter,
  little-endian). The kernel never re-issues an op id younger than the store's retention. The boot
  incarnation enters the audit preimage (a RED: two boots, the same unit key, distinct records).
- **Store v3 money slots (ARCHITECT rulings 2026-09-27/28; the model is `busbar-contract/src/slice.rs`:
  a draw is (bucket, dimension, wanted, epoch), dimension ∈ {nano-units, requests, concurrency,
  class}, a chain draw all-or-nothing).** Request-path ops carry fixed unit cells, never a JSON map
  (§11.11 M8): `reserve` is ATOMIC — if any cell grants 0 the store applies nothing and answers FAILED
  (Exhausted, StaleEpoch, Unavailable or NoCap) naming the first ungrantable cell; `slice_release`
  clamps each release to what that slice has left and never returns more than was granted; the usage,
  metering and audit batches are off-path write-behind, applied in order, atomic per batch. Each cell
  names its own window start (0 = a gauge that never rolls); the kernel pushes window caps at open,
  at refresh and before a window's first reserve — a whole push is atomic, a higher config generation
  wins, an equal generation with a different cap is refused `STORE_CAP_CONFLICT`, a reserve on a
  window with no cap fails NoCap. **Dedupe:** the same op id replayed re-writes its ORIGINAL results
  into the new buffers and applies nothing; "same" means the op's value fields, never buffer pointers;
  only an op that APPLIED a change is recorded (a FAILED, REFUSED or short answer is not, and a retry
  is judged afresh); the capacity check precedes the replay lookup; retention is durable, survives a
  store restart and lasts at least 24 h; the same op id with a different body is REFUSED
  `STORE_OPID_CONFLICT` and nothing applies (OWNER-approved 2026-09-28, registered as new surface). A
  partial grant is sized exactly as the 1.5.5 in-tree store sized it; `used + amount` is checked, and
  overflow is Exhausted.
- **1.5.x usage rows (#33; OWNER rulings 2026-09-29).** The engine holds no fold: 1.5.x rows live in
  the store plugins' own databases, so each store plugin's `migrate()` upgrades them (scalar `tokens`
  onto `usage_units`) in its own crate; the contract carries no fold (`abi::sdk::store_migrate` was
  deleted by ABI-TRIM F10b, 3387366e3), crash-idempotent, proven per backend against rows written by the pinned 1.5.5 binary read back
  byte-identically. This migration conformance is a HARD gate (M5): no store sibling opens a 1.5.x
  database, and the legacy 1.5.5 store wire does not retire (M6), until every backend passes it; CI
  fails on a missing fixture or cdylib and runs the migration-fixture script; network backends run in
  Latchkey. #21: the per-request fee counts at admission, as 1.5.5 did. #32: a retroactive RATE
  correction that would cut inside a stored row is refused with a clear error; `adjust` is untouched;
  no storage change. #34: the currency leaves the audit digest (digest v3); v2 records still verify; the
  public audit range read gains a per-record `recipe` field so mixed batches verify — additive, and
  flagged to the owner.
- **Owner money rulings 2026-09-28.** Refund across a window refunds the bucket actually charged —
  1.6.0's behaviour ships as a `breaking` accepted difference (M-1). The decisions plane bills one
  `decision` per successful, settled answer from every provider; its card prices `decision`,
  `input_tokens` and `output_tokens` (family `decision`, all three required, 0 = free); the hosted
  provider keeps 1.5.5's `/usage/units` as the decision count (DECISIONS D9, 2026-09-30).

- **One clock for prices.** A price instant is read from the same clock the rate-card history is dated
  on — never lifted, truncated or derived from a coarser bucket key. The instant is
  `max(bucket_start, priced_from_ms)`: the era picks the card, the clip keeps the instant inside the
  row's own span so a back-dated correction window can contain it. Any two events compared for order
  come from one clock.
- **The budget gate prices at admission.** `price(ledger_slice, card_history)` is pure; if a memo is
  needed it is keyed on `(ledger slice identity, card-history epoch)`, lives in memory and is NEVER
  persisted (a price stored on a row is `spend_cents` under a new name). Measure before building it.
- **Money proof is the function's own test with pinned values**, including the mid-window case; the
  oracle's clock fields (`as_of`, `start`, `end`) are pinned per cell, never normalised to zero.
- **The a2a billed byte** (Q35): payload bytes relayed both ways per hop (request + response body),
  class `bytes`, priced by `agents.rate_card` keyed `agent:<id>`; no card → 0; a card silent about an
  agent refuses (#42); a hop refused before the socket ledgers nothing.

*Proven by:* the oracle's billing, ledger and teller families; kill -9 during a stream; the
cut-stream failover cell, which asserts the client's error frame and the one Abort line; the streaming
conformance rig's session legs (admit at open, checkpoints, one sealed line).

### 8. Cleanliness crates

Exactly three crates are compiled in and are never plugins; each depends one way on the kernel,
names no plugin, and gets its listeners through the connector.

| Crate | Owns | On the request path |
|---|---|---|
| `busbar-core-admin` | the operator surface | no |
| `busbar-core-oauth2` | the authorization server and the hosted login flow | no |
| `busbar-core-connector` | composition; TLS — the only holder of TLS keys, certificates, trust roots and mTLS identity, sourced through secret plugins; per-worker pools; ALPN; the proxy; URL joining; the transport registry; ~~the cold-I/O runtime; carrying auth objects to framers~~ (SUPERSEDED 2026-09-27 by THE DESIGN §11.2 and §11.6: no cold lane; the kernel makes the auth call) | **yes** |

The connector is not kernel, because it understands TLS and composition. It is not a plugin, because
it holds TLS keys. It also owns the secure layer's DTLS engine and the udp carrier (§5), and every
listener (§3).

### 9. Crates and repos

The busbar repo holds **15 crates**: `busbar` (the binary and composition root), `busbar-kernel` and
its 8 workflow crates, `busbar-contract` (the shapes and the author SDK), `busbar-plugin-loader`, and
the three cleanliness crates. Every plugin lives in its own repo, named `busbar-<kind>-<name>`:

| Kind | Plugins |
|---|---|
| plane | llm, mcp, a2a, streaming, decisions |
| transport | tcp, stdio, http, ws, grpc (grpc OWNER 2026-09-29; there is no unix transport, OWNER 2026-09-30, Q127) |
| store | memory, postgres, mysql, sqlite, valkey |
| secret | env, file, vault |
| auth | admin-tokens, github, ldap, oidc, webhook-signature; the connection-auth styles' crates are an owner question (§6) ~~outbound~~ |
| hook | ranking, webrequest ~~headroom~~ (OWNER 2026-09-30: "Delete hook headroom 100% keep the repo but remove from website"; the repo stays, outside the fleet) |
| export | prometheus, webhook, file, otlp |

The `decisions` plane keeps `"decision"` as its key and meter class. Each plugin repo is a logic crate
plus a plugin crate, has its own semver and declares its kind's ABI version (§11.2) ~~a declared
contract-ABI range~~, promotes on its own dev → qa → main, and is generated and checked from
`plugins.yaml` and `.github/fleet/`. The default distribution pins exact plugin versions, and core
refuses a plugin built for any version of its kind other than the current one (§11.8) ~~outside its ABI
range~~ (SUPERSEDED 2026-09-27 by THE DESIGN §11.2 and §11.8).

**The legacy engine folds (ARCHITECT rulings F1-F26, 2026-09-28; OWNER 2026-09-28: one Opus agent per
plane, plan first, landing serially).** A pure MOVE is a byte-identical line move (#19). Code that must
become sans-IO, contract-only plane code is a REWRITE, and its identity proof is the oracle for llm and
core surfaces (wire bytes against the 1.5.5 golden) and, for the planes new in 1.6.0, the plane's
conformance rig, the tests and the money suites against current `predev` — plus the plane
conformance suite and, for a `$` step, the money suites. Folds consume the prerequisite steps
(host tables, the plane driver, the connector, http, auth, the money chain); they never build them.
The legacy operation-handler and codec-registry cells die with the registry at step 36. A JSON-RPC
reader shared by two planes is a pure, stateless helper in `busbar-contract` outside `abi/` (no
statics, no I/O, no lateral plane edge). The trust lifecycle is the kernel's (§11.12); URL judging
inside arguments is a host call at the point 1.5.5 made it; RFC 8707/8693 token exchange is the auth
kind's `exchange()`. Whole-App tests move to `crates/busbar` integration tests and the conformance
suites, and test counts never fall; before any engine deletion a per-test coverage map names the new
home of every test, and no test retires without an ARCHITECT ruling (F25). Of two implementations,
the SERVED one is the base and the unserved one merges in or is deleted, with proof (F11). A move that
raises the destination crate's cells is accepted only when the pair nets down in the same commit
(F12). Unit steps land in their kernel crates (admit → budget, meter/usage → ledger, audit → audit,
verify/approve → scope, authenticate → identity). A plane reading its own declarations instead of the
kernel's protocol registry is an accepted mechanical change. The hook projection is supplied by the
plane (Part 3 §12), and 1.5.5's hook tests land verbatim. Health probers become the kernel breaker's
probe units (Part 3 §12). A fold removes `tracing` from its plane in favour of #85 diagnostics under the
library rule (§2). Folds stop at in-tree `crates/busbar-plane-*`; repo extraction is step 40. The plane
is `streaming` everywhere a plane is named (key, crate, feature, lanes, admin noun, pools, diagnostics);
`voice` survives only as a dialect name inside it (OWNER 2026-09-28). The codecs fold into their planes
(R7), and `DialectCodec`/`ProtocolDecl` move out of the contract into the llm plane, after which the
contract names no http (ARCHITECT, 2026-09-30).

### 10. Owner questions — decided 2026-09-27

The owner answered every question this section held on 2026-09-27. Each item below is a ruling and
binds the design; the rows in `1.6.0-QUESTIONS.md` keep the options and the cost of each.

- **Q79-fork-refusal — RULED 2026-09-27, as recommended:** a store refuses a different record at an
  already-used task-event sequence as a fork, as the sqlite store does, where the published plugin
  overwrote; signed as an accepted difference.
- **mysql-ldap-stream — RULED 2026-09-27, as recommended:** patch both drivers to take a
  host-supplied stream, so the mysql store and ldap auth reach their servers through the connector;
  both plugins ship in 1.6.0 (R5).
- **ABI versions — RULED by the owner 2026-09-27:** *"ABI version should be 1 + what is in 1.5.5. if
  we changed it 32x in 1.6.0 thats not ABI + 32. Use what went to prod in 1.5.5 + 1 for all ABIs."*
  Every ABI version constant ships as its v1.5.5 value + 1 (a constant new in 1.6.0 ships as 1);
  pre-release changes never bump a version — appends during development are guarded by the layout
  golden and append-compat tests, not by the number. ~~Each kind's loader window admits its v1.5.5 value
  and the +1 value, so published 1.5.5 plugins keep loading (the 2026-09-19 pairing).~~ **SUPERSEDED
  2026-09-27 by THE DESIGN §11.8:** the loader accepts only the current version of each kind and
  refuses newer-than-host. The constants stay per ABI — one per kind (§11.2); collapsing them to one
  number is not the ruling.
- **cloud-metadata — RULED 2026-09-27, as recommended:** the `operator-infrastructure` egress class
  refuses cloud metadata hosts (§5), recorded as an accepted difference.
- **norm-rules-accepted-difference — RULED 2026-09-27, as recommended:** yes — #79's PostConfigApply
  register entry adds the `norm.rules` class and carries the corrected rationale.
- **own-socket-legacy-plugins — SUPERSEDED 2026-09-27 by THE DESIGN §11.8** (no legacy loading: no
  published 1.5.5 JSON-contract plugin loads, own sockets or not). ~~RULED 2026-09-27, as recommended:
  published 1.5.5 plugins keep loading through the legacy-artifact class (§2) unless they open their own
  sockets; those are refused at load, naming the fixed release, recorded as an accepted difference. This
  is the owner's reading of the 2026-09-04 and 2026-09-19 rulings: a published store that dials its own
  database upgrades with busbar.~~
- **refusal-names-no-amount — RULED 2026-09-27, as recommended:** a refused request of a plane new in
  1.6.0 is unpriced and its refusal names no amount or budget (§7); mcp counts as new, so its
  `prompts/get` change stays as landed. The llm plane's refusal bytes stay 1.5.5's.
- **stateful-handles-webhook — RULED 2026-09-27, as recommended:** the stateful-handle capability and
  the inbound webhook receiver ship config-reached (off unless configured, Law 7), not behind a cargo
  feature, on the recorded security terms: verify signature and origin, refuse replays, correlate only
  through the anti-enumeration scoped lookup, every denial indistinguishable. A 1.5.5 llm config sees
  1.5.5 bytes.
- **mcp-a2a-over-ws — RULED 2026-09-27, as recommended:** the ws framer is a kind-neutral transport
  plugin any plane can declare (§5), and that is the generality; mcp and a2a serve exactly the
  transports their published specs define, and no ws binding is built for them.
- **release-keys-relabel — RULED 2026-09-27, as recommended:** the loader's release-key marker becomes
  a plain doc line naming the three guards (the build exports the public key, the key guard refuses a
  release build without a well-formed key, the release gate fails the row without it), and its
  waiver is removed.
- **gemini-tool-use-billing — RULED 2026-09-27, as recommended:** the owner's 2026-09-07 ruling stands —
  a grounded Gemini turn bills Google's total, tool-use prompt tokens included, a registered money
  improvement; the DONE list names it as signed (Part 5).
- **reserved-tier-absent-is-zero — RULED 2026-09-27, as recommended:** an absent reserved token tier on
  a rate-card entry prices at 0, as 1.5.5 read it; that is #77(5)'s one scoped exception. Classes
  under `units:` still refuse when unpriced.
- **rate-card-version-visible — RULED 2026-09-27, as recommended:** the rate-card version is served on
  the usage and audit responses as an `additive` register entry (#44, #10).
- **cross-node-revoke-propagation — RULED 2026-09-27, as recommended:** revoke, rotate and
  `enabled=false` keep 1.5.5's cross-node bounds.
- **memory-store-data-dir-history — RULED 2026-09-27, as recommended:** `/usage` after a restart is
  identical to 1.5.5 — a memory-store node keeps no usage history across a restart without an explicit
  opt-in, `data_dir` or not.
- **jemalloc purge crash — RULED 2026-09-27:** no 1.5.x hotfix; the fix ships in 1.6.0 only.
- **Accepted differences ruled 2026-09-28 (OWNER):** D-1 "diagnostic codes" — the register's expected
  cells go 480 → 481 for the extra `boot.refusal|BOOT-MCP-01|validate` cell (new 1.6.0 surface, no
  1.5.5 golden, in accepted-gaps; it forgives nothing new); refund across a window (§7, M-1
  `breaking`); `STORE_OPID_CONFLICT` (§7, new surface); the three LDAP differences (§6); the door-only
  gate's +56 rows from the codec fold are relocated debt that drains with the legacy engine fold. The
  a2a and mcp egress fences are recorded from a clean `predev` build (ARCHITECT, 2026-09-28), and a
  fence never pins a known defect: a capture waits for the fix (ARCHITECT, 2026-09-29).
- **The plugin ABI — LOCKED by the owner 2026-09-27:** §11. It SUPERSEDES the `own-socket-legacy-plugins`
  answer (Q86 in `1.6.0-QUESTIONS.md`), whose "published 1.5.5 plugins keep loading" no longer holds, and
  the loader-window half of the ABI-version ruling above. Q86 was SUPERSEDED 2026-09-27 by THE DESIGN §11.8.

### 11. The plugin ABI — OWNER-LOCKED 2026-09-27

The owner locked the plugin ABI on 2026-09-27. Where §2, §5, §6, §10, a Part 2 row, Part 3 or Part 4
disagrees with this section, this section wins, and the text it contradicts is struck in place with
"SUPERSEDED 2026-09-27 by THE DESIGN §11.N".

**11.1 Plugins speak the memory ABI only.** Owner: *"Plugins speak Memory ABI ONLY."* The COLD/JSON
lane is abolished. #30's two lanes are gone: there is no JSON lane, no per-call serialisation of a
plugin call, and no kind is "cold". Every kind of plugin is called through a table of function
pointers over data in fixed C layout.

**11.2 Seven ABIs, one per kind, on one shared mechanism.** Owner: *"BINGO LOCKED"*.

The **shared mechanism** is the same for every kind:
- one table of function pointers; data in fixed C layout;
- every call returns **Ready** or **Pending(wake)** — not ready, with a wake the plugin fires on
  completion (this document says "not-ready" for the second result);
- memory a plugin returns is plugin-owned and valid until that plugin's next refresh generation;
- no allocation and no blocking on the hot path;
- slow I/O returns not-ready and fires the wake on completion — never a blocking thread;
- setup and refresh go through `open`, `refresh` and `tick`;
- every operation carries the `extensions` blob;
- every reply carries the metrics and diagnostics envelope (#85);
- one entry point per plugin, one loading path, one dispatcher.

**Plugin logging.** Owner: *"they should be consistent. all plugins should log to their plugin's
log file. no logs for plugins is not an option."* This is the ONE rule, for every plugin of every
kind, compiled in or dropped in. Whatever a plugin logs during a call, through `tracing` or `log`,
from its own code or from a library inside it (`h2`, `hyper`, ...), becomes a log diagnostic
(`DIAG_LOG`) on that call's #85 envelope. The HOST writes it to that plugin instance's own log
file. The door macro's trampoline runs every slot body under a per-call scoped capture: a `tracing`
dispatcher that is the thread's default only while the body runs, fed `log` records by
`tracing-log`'s `LogTracer` (the plugin image installs it, and so does the host). The capture lives
in one slot per thread per plugin image. The host bounds each reply at 128 records and 64 KiB; the
rest, plus whatever the plugin's own capture could not carry, is one counted line. It filters by
the instance's level and writes `<dir>/<instance>.log`, one record per line (`time LEVEL instance
kind target: message`), rotating by its rename rule. The keys are `plugins.logs`: `dir`, `level`,
`levels`, `rotate_mb` and `keep`, set live through `POST /config/apply`. A plugin never writes to
stdout, stderr, a file or a global logger itself. What it writes outside a call (from another
thread, or to standard error) reaches no plugin log. The proof is the same plugin, linked and
dropped in, writing byte-identical files. This changes where logs go relative to 1.5.5: plugin
lines leave the host log for per-plugin files, which #85 allows ("log changes from 1.5.5").

**Per kind**, and only per kind: its own operations, its own data shapes and **its own version
number**. Each kind's version is its v1.5.5 value + 1; a kind whose ABI is new in 1.6.0 ships 1. A
kind evolves without forcing any other kind's plugins to rebuild. The shipped numbers:
`MECHANISM_VERSION` 2; store 3; secret 2; auth 3; hook 2; export 3; plane 1; transport 1. The loader
checks the manifest's mechanism version before `dlopen`, then the door symbol, then the magic, the
mechanism version and the kind version: an older kind version is refused naming the rebuild, a newer
one is refused (ARCHITECT, 2026-09-27; fleet plugins declaring older numbers move to these at their
port).

**11.3 JSON is only a payload.** JSON appears only as a pointer + length blob inside a field, for data
that is naturally a document or likely to grow. On the request path the kernel never builds JSON per
request: what the kernel builds is fixed fields and small arrays, and data it already holds as JSON
(the request body) passes zero-copy. Each kind's contract definition decides, once, which fields are
fixed and which are blobs.

**11.4 A plugin is a plugin — compiled in or dropped in, the same table.** Owner: *"compiled or
dropped in is just a convenience for customer; NOTHING CHANGES about the plugin itself and how it
works."* A compiled-in plugin exports the same door and is called through the same table as a
dropped-in one. The kernel never holds a plugin crate's Rust types and never calls its Rust
functions.

*The state being fixed, measured 2026-09-27:* only the export kind reaches its compiled-in plugins
through the ABI; store, hook, secret, auth, transport and plane bypass it, and the both-ways tests
mostly compare the Rust API against the ABI rather than one build against the other.

*The proof, per kind:* ONE conformance suite that runs the SHIPPED compiled-in build and the dropped-in
build through the same table.

**11.5 One place for every ABI shape.** Every ABI shape lives only in `busbar-contract/src/abi/`:

```
abi/mechanism/                     the shared mechanism (§11.2)
abi/store/ abi/secret/ abi/auth/ abi/hook/ abi/export/ abi/plane/ abi/transport/
                                   one folder per kind: its operations, shapes, version
abi/host/                          the host tables every kind calls (conn, clock, …)
abi/sdk/                           typed wrappers for Rust authors
+ a generated C header             the zero-dependency proof (#84)
```

A gate fails CI if any ABI shape — a C-layout struct, an ABI function-pointer type or an ABI version
constant — is defined outside `busbar-contract/src/abi/`. **Changing a kind** is: edit its folder
(plus its sdk wrapper, the regenerated header and its version bump) → the kernel dispatcher → every
plugin of that kind implements it. The kind's conformance suite is the finish line.

**11.6 Auth is on the memory ABI.** A transport calls its bound auth only at the auth points of THE DESIGN §6 ('Auth points and guest lists'), through the host auth handle; every call crosses the one dispatcher, and the kernel keeps no verified-credential cache (§11.11 R3).

**11.7 Hooks are on the memory ABI.** Gates, rewrites and base-ordering are on the request path; the
request body passes zero-copy as a blob. Hook behaviour stays 1.5.5's (#85): reply precedence, the
status clamp, the message cap, `on_error` and the taps. ~~The 1.5.5 thread leak on a timed-out hook call
becomes structurally impossible: a slow hook returns not-ready, and there is no blocking thread to leak.~~
**SUPERSEDED 2026-09-27 by THE DESIGN §11.11 (Q-LEAK, owner ruling R1):** workers are thread-per-core; a
hook that sleeps or spins in `decide` freezes its whole worker, not just the calling instance, and a slow
hook returning not-ready does not by itself get the wedged call off the worker. So: **every hook call —
not only one a plugin marks `cpu_heavy`, and with no per-plugin flag — runs on an off-worker lane
carrying 1.5.5's `timeout_ms` guarantee.** A crossing watchdog plus worker replacement contains a call
that is actually wedged: the watchdog trips at the deadline, the wedged worker is abandoned (never
rejoined, never trusted again) and a fresh worker takes its slot, so only that worker's in-flight work is
lost, not the whole fleet. The two 1.5.5 timeout tests, `dlopen_decide_deadline_cuts_off_a_slow_gate` and
`dlopen_slow_gate_hits_the_deadline`, must pass as written — no rewrite. This lane's cost is measured in
the PERF phase (§11.9), not gated before it.

*The hook kind as ruled (SEH, WIRE-HOOK; ARCHITECT rulings 2026-09-27/30).* The body reaches a hook as
the raw request bytes, zero-copy (an octets blob; the SDK's decoded views borrow it); the plugin or
its SDK parses. The stage view carries the full 1.5.5 hook stage projection and `decide` the hook
context's budget; signals are tagged values (u64, i64, f64, string, bool) so the SDK renders
byte-identical 1.5.5 JSON; the ABI's field names are neutral and the SDK maps them to the frozen 1.5.5
keys. `decide` and `transform` answer EXACTLY one verb bit (decide: prefer, abstain, reject, restrict;
transform: rewrite, abstain, reject) — there is no precedence rule — and a reject status without the
reject verb is FAULT. A rewrite is 1.5.5's rewrite JSON, parsed kernel-side, fail-closed. The
watchdog's budget is the hook's `timeout_ms`; quarantine (R2) backs off from 1 s, doubling to 30 s,
then makes one trial call on a fresh instance, and while quarantined a call waits for the trial window
within its own deadline, never beyond it. `notify` carries the signals and, only under a `prompt: ro`
grant, the prompt view (messages as role and text), and its JSON is byte-exact 1.5.5; the tap is THE
notify path. A hook's `serve` is a separate row (new surface). The final wiring commit deletes the JSON
notify path and the dlopen policy and adds a RED that a 1.5.5 JSON hook plugin is refused at boot. An
export scrape's families are the WHOLE snapshot, in the 1.5.5 recorder's order (kind, then name).

**11.8 No legacy loading.** Owner: published 1.5.5 JSON-contract plugins no longer load. Every
first-party plugin is rewritten; a third party rebuilds against the 1.6.0 SDK. This is an owner-signed
customer-visible break: boot refuses such a plugin with a message naming the rebuild. The loader
accepts only the current version of each kind and refuses a plugin built for a version newer than the
host. This replaces the `own-socket-legacy-plugins` answer (Q86) and the "loader admits the v1.5.5
value" half of the ABI-version ruling (§10). An accepted-differences `breaking` entry, a named
CHANGELOG line and an SDK migration note are owed (`1.6.0-TODO.md`, KERNEL<>PLUGINS).

**11.9 Performance is its own phase.** Order (OWNER 2026-09-30): CODE → DEV-GREEN → PERF → fixes → DEV-GREEN
again. PERF runs only on the frozen DEV-GREEN sha (no point measuring code that is still changing): a
full A/B against published 1.5.5 with no fixed numbers — throughput as high as possible, 2× 1.5.5 being
the floor and not the stop; peak memory as low as possible; a zero-allocation hot path; binary size is
not a goal; the loop runs until the gains run out — on a fixed reference machine (an ephemeral EC2
instance, terminated after); then the fixes; then DEV-GREEN is proven again.
**The method (OWNER, 2026-09-29/30):** one cell, openai → openai, on the `GetBusbar/benchmarking`
harness; both binaries built the shipped way (PGO, BOLT, LSE atomics on arm64, fat LTO, one codegen
unit, strip, jemalloc — build-posture parity is not negotiable); CPU and allocation profiles drive
each round. **Every result is reported twice, raw and machine-adjusted:** ratio = gateway rps ÷ that
run's no-gateway machine check (`box_qualify.observed_rps`); runs are compared by ratio, never by raw
rps from different machines, and 1.6.0's ratio ÷ 1.5.5's ratio is the code speedup. The 1.5.5
baseline is owner-accepted (the numbers and the exact command are in `1.6.0-TODO.md`, PERF). **The
phase runs with the owner (OWNER, 2026-09-29):** no 1.6.0 performance run, PGO/BOLT build or tuning
loop starts until the owner joins; everything else reaches code-done first.
Before PERF only design-level checks gate: zero plane→host calls per chunk, a crossing under 1 µs,
and a zero-allocation hot path. The per-landing A/B trend line is a report-only record, never a gate.

**11.10 Execution model.** Owner: *"kernel has 1 way to load plugins, find out its kind, and use it as
needed. we just design the kind abis and spin up agents to implement for every plugin parallel"* —
*"5 planes, 5 agents implementing the same ABI interface, siblings"*. The order is: design the seven
kind ABIs (with an adversarial review); build the kernel side once (one loader, one kind lookup, one
dispatcher, the SDK and the generated header, one conformance suite per kind, the ABI-location gate);
then fan out one agent per plugin, siblings per kind. `1.6.0-TODO.md`, KERNEL<>PLUGINS, holds the list.

**11.11 The signed kind-ABI design — owner review round 2, ruled 2026-09-27.** §11.1-§11.10 locked the
shape; a two-round adversarial review (hot path, parity, contract lenses) then read it against the
tree at `b48a79a9a` and against v1.5.5, and disagreed on nine points. The owner ruled on all nine.
Where this subsection conflicts with an earlier §11.N, THIS SUBSECTION WINS (§11's own rule at the
top of this section) and the earlier text is struck in place citing §11.11.

**What the review changed, going in.** Store: all ten 1.6.0 ledger operations become real store v3
slots; additive writes carry an `op_id` and the store dedupes on it; record blobs use the tree's
unit-map shapes plus the scale marker, not "1.5.5 serde bytes"; the migration read moves into the
kernel. Auth: the inbound credential cache stayed in the kernel, unresolved until Q-INCACHE was
answered below;
caller-credential passthrough is restored; SigV4 gets its request inputs; before the first token mint
a call returns READY with no fields, giving the upstream 401 as in 1.5.5; inbound SigV4 moves into an
auth plugin. Hooks: `configure`, `status` and `describe` run on a fresh management instance and
return the 1.5.5 blobs; taps use a host pool with the global cap of 1024; an `infallible` fact carries
the `weighted` rule; the reply sanitiser runs host-side. Mechanics: slabs are per worker with no
atomics except the wake push; each operation has a deadline class (call, stream, connection,
write_behind); memory for an operation whose call can return not-ready never lives in the worker's
scratch pad; a
crossing watchdog runs in every build (§11.7); the host pre-fills `out`. Plane: every piece reports
cumulative units and `cancel` returns a disposition; backpressure uses `emitted`/`more`; `rate_card`
and `fees` are stripped before any blob reaches a plane. Crates: the contract crate loses all its
statics; `busbar-llm`, `busbar-mcp`, `busbar-a2a` and `busbar-voice` fold into contract-only plane
crates; the `plane-*`, `hooks-ranking` and `auth-admin-tokens` kernel features are deleted; transport
http becomes a sans-IO rewrite. Retired outright: the cold symbols, `.init_array` registration, the
`ABI_MAJOR`/`ABI_MINOR`/`POD_VERSION`/`TRANSPORT_DECL_MAJOR` constants, `STORE_ABI_FLOOR` and the
`poll` slot.

**R1 — Hooks (Q-LEAK).** Ruled in §11.7: every hook call, not only `cpu_heavy` ones and with no
per-plugin flag, runs on an off-worker lane carrying 1.5.5's `timeout_ms` guarantee; a crossing
watchdog plus worker replacement (abandon the wedged worker, spawn a fresh one) contains a call that
is actually wedged. The two 1.5.5 timeout tests, `dlopen_decide_deadline_cuts_off_a_slow_gate` and
`dlopen_slow_gate_hits_the_deadline`, must pass as written. Its cost is measured in the PERF phase (§11.9).

**R2 — Quarantine.** A wedged hook comes back through a timed probe: circuit-breaker discipline —
backoff, then one trial call, promote on success. It is registered as an accepted difference from
1.5.5 (`1.6.0-TODO.md`'s accepted-differences register), since 1.5.5 had no quarantine to exit at all.

**R3 — Q-INCACHE.** The inbound credential cache moves OUT of the kernel and into the auth plugins,
as the plugin's own internal cache (the SDK ships no cache helper), flushed through its own `refresh`. The kernel
keeps only Pass buffering (the short-lived buffer that lets a body be replayed once verification
completes) — no verified-credential cache of its own. This supersedes the "stays in the kernel
unresolved until Q-INCACHE was answered" line above and closes Q-INCACHE.

**R4 — Q-DISK.** A host-owned bounded disk lane is the ONE exception to "no blocking" (§11.2's rule
otherwise holds absolutely): it exists solely for the SQLite store and the file export sink, both of
which are inherently local-disk-bound and cannot be made sans-IO without becoming a different product.
No other kind may claim this exception.

**R5 — Q-MYSQL.** A sans-IO mysql store and a sans-IO ldap auth plugin are built (the `mysql-ldap-stream`
ruling, Q82, patches both drivers to take a host-supplied stream); both ship in the default distribution.

**R6 — oauth2 and admin.** `busbar-core-oauth2` and `busbar-core-admin` stay core (§8), not plugins —
unchanged from §8's existing text. The door-only gate (§11's gate list, widened by this round) exempts
EXACTLY their two `OnceLock` seams (`oauth_as/seam.rs`, `admin/seam.rs`) and refuses any new
fn-pointer seam installed into the kernel by name (contract review BLOCKER 1: the bypass list was
incomplete because `door-only` did not scan for a static seam at all).

**R7 — Codec crates fold into their planes.** `busbar-llm-codec` and `busbar-voice-codec` (and any
sibling codec crate) fold into their plane crates rather than becoming standalone plugin-side
libraries; the kernel and the `busbar` binary never depend on a codec crate, directly or transitively
(closes contract review M10 — plane crates depending on a codec crate conflicted with "plugins depend
only on `busbar-contract` from busbar").

**R8 — Accepted differences.** Q-BODY is REJECTED: `ro`/`rw` hooks see exactly the 1.5.5 view, tools
and images included — no widened view ships. A 503 when auth verify is overloaded is ACCEPTED as a new
difference from 1.5.5 (register it). Q-EXPIRED is an accepted difference ONLY IF measurement shows
1.5.5 actually differs on the expired-token path; absent that measurement it is not registered.

**R9 — Data-struct evolution and the version rename.** Data structs grow extensions-first (the
`extensions` blob of §11.2/§11.3 is where a new field lives first); appending a genuinely new fixed
field to a struct's C layout requires a version bump of that struct's kind ABI — "append under
`honoured_size` without a bump" (contract review M7) is not a path this design allows, and it does
not conflict with extensions-first because it is a different mechanism for a different situation.
`TRANSPORT_VERSION` is renamed `MECHANISM_VERSION` and ships as **2** (its 1.5.5 value + 1, per the
existing ABI-version ruling, §10); the four pre-release counters `ABI_MAJOR`, `ABI_MINOR`,
`POD_VERSION` and `TRANSPORT_DECL_MAJOR` are retired, not renamed — nothing outside `abi/` may define
a version constant (§11.5's ABI-location gate covers this).
*Clarified by the owner 2026-09-28:* R9 governs the evolution of a SHIPPED layout. Until the 1.6.0 tag,
a kind ABI's first version is still being defined: a v1 layout edit lands with the layout golden
regenerated in the same commit and no version bump. From the 1.6.0 tag on, R9 applies unchanged.

**Implementation requirements the review's technical and contract lenses raised, ARCHITECT-owned —
each is a requirement, each carries the fix the review scoped for it:**

| # | requirement | the fix |
|---|---|---|
| H2 | Tickets carry a generation, `(slot, generation)`, so a late wake cannot resume a slot the host has since recycled to a different call | tickets are latched and spurious-tolerant: a wake against a stale generation does nothing |
| H3 | The tap view is never rebuilt as JSON per request (ruling 3, §11.3) | the tap pool holds a copy of the fixed stage view; any JSON a plugin wants, the plugin builds itself, off the request path |
| H4 | Off-path writes queued per request must not be unbounded-and-never-drop; 1.5.5 coalesced them per cell | coalesced batches, one `op_id` per batch, with durable dedupe retention on the store side |
| H5 | A `write_behind` call to a hung store must not stall reload drain | `write_behind` carries its own deadline class, distinct from `call`/`stream`/`connection`, and reload drain does not wait on it |
| H6 | Continuation and ticket ownership across a hook chain, and its sizing, must be a stated invariant, not left implicit | tickets are host-owned for the lifetime of the chain; a chain's continuation state is sized and documented per kind, not left to grow unbounded |
| M2 (contract) | The kernel names no protocol anywhere, including features and `cfg` sites — `jsonrpc-ingress`, `card-signing`, `relay`, `duplex-ws`, `egress-*`, `dispatch`, `openapi-schema` all named a protocol in the kernel | the nine kernel features are deleted (listed below); `c1-literals` is widened to scan all 7 kinds plus feature names and `cfg` sites |
| M3 (contract) | `extern "C-unwind"` across a foreign cdylib boundary is undefined behaviour | every door and table entry is `extern "C"`; an escaping panic aborts, it never unwinds across the boundary |
| M4 (contract) | Linked-plugin `tracing`/`log` output reaches the kernel subscriber; dropped-in output goes nowhere — an origin-visible difference `origin-blind` must catch | ~~`plugin-closure-deps` is extended to deny `tracing`, `log` and `std::thread`/`std::net`/`std::fs`/`std::env` in a plugin's dependency closure, so neither build can depend on host-visible logging or ambient I/O to begin with~~ SUPERSEDED 2026-09-28 by owner ruling: plugins may use any third-party library; the busbar-contract-only closure and host-owned sockets/TLS stand |
| M5 (contract) | Cargo feature unification can make a linked and a dropped build of the same plugin differ | a gate proves the feature sets are equal between the linked and dropped builds of the same plugin |
| M6 (contract) | The both-ways suite ran against the test profile, not the shipped binary, and "counters above 0" was too weak a pass condition | the both-ways suite runs against the release binary, with exact crossing counts asserted, not merely a nonzero count |
| M7 (contract) | "Append under `honoured_size`" conflicted with ruling 3's extensions-first rule; the draft also contradicted itself on FAULT pre-fill vs. zeroed `out` | resolved by R9 above (extensions-first; a fixed-field append is a version bump); the host pre-fills `out` (one rule, stated once, no FAULT-vs-zero split) |
| M8 (contract) | Store `reserve`, `slice_release` and record operations sit on the request path but carried JSON unit maps | store request-path money operations carry fixed `bb_units[]`, not a JSON unit map |
| M9 (contract) | The inbound cache was adopted before Q-INCACHE was answered | resolved by R3 above |
| M10 (contract) | Plane crates depending on the codec crates conflicted with "only `busbar-contract` from busbar" | resolved by R7 above |
| M2 (parity) | Quarantine had no exit rule and was not registered as a difference from 1.5.5 | resolved by R2 above |
| M3 (parity, money) | 1.5.5 never bills a translate-abort; it bills only provider-reported usage, bills 0 for a non-stream partial, and refunds the budget unit separately — the draft bet "unless failed" | plane cancel billing is pinned to these four 1.5.5 rules; the budget refund is a separate act, never folded into the cancel billing call |
| M4 (parity) | The http rewrite had no recorded 1.5.5 wire-byte oracle | step 20 (`1.6.0-TODO.md`) is re-scoped to the sans-IO http rewrite, gated by a recorded 1.5.5 h1/h2/grpc wire golden suite as its exit test |
| M5 (parity) | The rewritten export, store and secret plugins had no golden suite against 1.5.5 output; `op_id` dedupe durability was unstated | a golden 1.5.5 suite is owed for each export stream and each store backend; dedupe retention must be durable (ties to H4) |
| M6 (parity) | The hook view's budget and cost fields were not listed | every hook-view field is listed, each marked static or dynamic, in the hook kind's contract definition |
| M7 (parity) | The 503-on-overload and the unbounded queue were unregistered | the 503 is registered under R8; the queue is bounded per H4 |

**Gates.** `kind_abi_lane` is deleted (its two lanes no longer exist, §11.1/§11.3). Added, beside the
gates §11 already names:
- `one-memory-abi` — only the door symbol is exported anywhere in the plugin closure; no cold/JSON
  lane symbol exists.
- `abi-location` — every ABI shape and version constant lives under `abi/` (sharpens §11.5's existing
  rule into its own named gate).
- `contract-stateless` — no `static`, `OnceLock` or `thread_local` in `busbar-contract`.
- `plugin-closure-deps` — a plugin depends only on `busbar-contract` from busbar. ~~with no runtime or
  subscriber dependency; extended per M4 above to deny `tracing`, `log`, `std::thread`, `std::net`,
  `std::fs` and `std::env`.~~ SUPERSEDED 2026-09-28 by owner ruling: plugins may use any third-party
  library; the busbar-contract-only closure and host-owned sockets/TLS stand.
- `c1-literals` — the kernel names no plugin, style or protocol; widened per M2 (contract) to scan all
  7 kinds plus feature names and `cfg` sites.
- `door-only` — widened to the whole binary closure, plus a "no static fn-pointer seam installed into
  the kernel" check, exempting exactly the two seams named in R6.
- a feature-set-equality gate between a plugin's linked and dropped builds (M5, contract).

Kernel features deleted: `jsonrpc-ingress`, `card-signing`, `relay`, `duplex-ws`, `egress-stream`,
`egress-auth-gate`, `egress-seam`, `dispatch`, `openapi-schema` — in addition to the `plane-*`,
`hooks-ranking` and `auth-admin-tokens` features this section's opening list already retires.

**Migration order.** M0 ABI-SPEC (the §11.5 layout, the constants test, the gates above — report-only)
→ M1 DISPATCH (generation tickets, driver tickets, completion handles, deadline classes, the watchdog
plus worker replacement) → M2 GATES → M3 TABLES, kinds smallest first: secret, store, hook, auth,
export, transport, plane → M4 HOOK-PARITY (the 184 v1.5.5 hook tests: 70 of llm origin + 114 kernel/loader/ranking) / M4b AUTH-PARITY / M4c
STORE-MONEY → M5 ZERODEP, with PLANE-FOLD inside it and the http rewrite at step 20 → M6 COLD-DELETE,
last. The full row-by-row order is `1.6.0-TODO.md`, KERNEL<>PLUGINS, THE PLUGIN ABI LOCK.

**Stop or change now, per this review:** delete the blocking `deadline` parameters on
`abi/host/conn.rs`'s `read`/`wait` (landed at `d4671c960`) before anything builds on them; add no new
kernel `OnceLock` seam beyond the two R6 exempts; nothing new on the cold/JSON lane; no new
`LinkedEntry` variant or Rust registration table (`PLANE_HOOKS` and similar); no new `static`,
`OnceLock` or `thread_local` in `busbar-contract`; ~~no tokio, hyper or `std::thread` in a plugin
crate;~~ SUPERSEDED 2026-09-28 by owner ruling: plugins may use any third-party library; the
busbar-contract-only closure and host-owned sockets/TLS stand;
stop hyper-based http transport work; no new protocol-named kernel feature or `cfg` site; AUTH-ROW
(step 8, landed 658fe02e7..0e54934f3) removed the admin-tokens call but the inbound cache itself was
correctly left alone until Q-INCACHE, now answered by R3; no further kernel dependency from a
step-34 plane move.

**11.12 Host services — owner-approved 2026-09-28.** Every host service a plugin calls beyond the
connector sits in ONE table, `HostSlots`, in `abi/host/`, on the connector's call shape:
`svc(ctx, in, out)`, `extern "C"`, answering the mechanism's outcome; every `in` leads with the
service head and its completion handle; a service that cannot finish answers PENDING and wakes the
handle's ticket, and on resume the plugin re-issues the SAME handle and receives the stored result —
the host never runs a service twice. `HostTables.conns` is swapped to the connector table first;
`HostSlots` is appended after it. Names obey the neutrality witness (Part 4).

| Family | Ops | What it is |
|---|---|---|
| clock | `clock.now` | wall and monotonic time from the kernel's one clock (§1); never pends |
| records | `records.get`, `records.list`, `records.claim` | the calling plane's own records (its Statement's record kinds only), through the store's plane-record slots. Reads see the instance's own queued write-behind batch (read-your-writes within the instance). `records.claim` is a one-time put-if-absent with a TTL (a store slot): the ONE path for approval redemption and replay refusal |
| dest | `dest.judge` | judges a destination named inside content against the egress rules (allow-list, class, cloud metadata hosts) without dialing, at the same point and with the same refusal timing as 1.5.5; its name resolution may pend. Asked to resolve (`DEST_RESOLVE`) and admitted, it writes every address it judged into the caller's buffers, one span each: the set a plane-originated dial is pinned to (`EstablishIn.within`, the dial-pin appends below) |
| sign | `sign` | signs bytes with busbar's key under the plane's declared signing domain and key-id prefix; refused for a plane that declares none. The plane assembles its envelope itself |
| unit | `unit.nest` | runs a nested unit on whatever plane serves the named claim, as a child of the calling unit (its principal, its audit correlation, accruing against its admission), depth-capped; the reply comes back whole and buffered. The kernel never learns what the child is |
| work | `work.open`, `work.find`, `work.settle`, `work.resume` | durable work handles (§1: never evicted; a bound refuses at admission; retention bounds only settled handles; the sweep runs on submit). `work.find` is the anti-enumeration scoped lookup: every denial answers alike. `work.resume` only binds the record: a continuation is a NEW unit with its own arrival, admission and window |
| trust | `trust.sight`, `trust.due` | the kernel-owned trust lifecycle over a generic counterparty: the plane reports a catalogue hash and the kernel judges it (new, same, drifted, quarantined); pinning and demotion are kernel state; `trust.due` names the counterparties the kernel's `tick` marked for re-verification |
| verify | `verify.lookup`, `verify.store` | the host-side verify cache with single-flight leadership: hit, lead (the plane fetches and stores) or follow |
| entitlement | `entitlement.check` | caller→target entitlement (the catalogue visibility filter) |
| content | `content.scan` | in-session content governance: a piece of content passes the gate that governs it |
| hook | `hook.call` | a hook stage run for an in-session sub-operation, over the hook kind's own `RequestView` |
| auth | `auth.call(point, …)` | a transport's call to the auth bound to its line or binding, owner-scoped; may pend; completion-handle and short-buffer rules apply |

**The short-buffer rule for services.** The caller is the plugin, so a service writes its result
into PLUGIN buffers the `in` names (pointer + capacity). The service `out` carries `needed_*` per dimension. A
plugin declares its maximum buffer sizes at `open` and preallocates them. A short answer is FAILED with
every `needed_*` at its full size, at least one above its capacity, and nothing applied or written;
the PLUGIN re-calls once, on the same handle, with at least `needed_*`, and the re-call reads the
stored result without acting again. A second short answer on that handle is FAULT for the service
call, and the plugin's op that made it answers FAULT.

**A service that may pend is callable only inside a ticketed op.** A pure op (`arrive`, `refusal`,
`project`) or any call made with no ticket that calls a may-pend service gets REFUSED, never PENDING;
a RED test holds the rule for every may-pend service.

*Proven by:* the `HostSlots` layout golden; one RED test per service validator arm; the may-pend
refusal RED; a compiled-in and a dropped-in plane calling every service through the same table.

**Who is calling (H2, ARCHITECT rulings 2026-09-29).** The loader records the caller when an instance
binds: `Caller{instance, plugin, kind}`, where `instance` is the configured instance LABEL (unique per
opened instance), `plugin` the Statement name. Every per-instance host registry keys by label, and a
call from an instance the kernel has not admitted is REFUSED (two instances of one plugin get two
registries — a RED). `records.*` are keyed by (label, record kind) and read through the store's typed
record slots, the schema being the caller's record kind; a per-instance pending-records overlay gives
read-your-writes, filled and drained by the driver's batcher. `records.claim` reuses the store's
put-if-absent-with-expiry slot (no new store op); a zero TTL is refused by the validator; the
idempotency key is `sha256(instance ‖ 0 ‖ kind ‖ 0 ‖ key)`. Trust policy comes from the kernel's trust
section: NEW, SAME, DRIFTED (once), QUARANTINED; re-sighting the pinned hash clears it; the demotion
record is durable and keyed (instance label, counterparty), and a 1.5.5 row without a label maps to the
plane's implicit first instance. A signing-domain collision is refused at admit. **`hook.call` is op
17 (K5 owns the ABI and the host side):** a gate or a rewrite over the hook kind's `PromptView`; a
chain resumes with `from: u32` (0 unchanged, 1+i rewrote, 400-599 stop; at most 255); **the gate scope
comes from the CALLING UNIT's kernel-recorded plane and pool, never from view fields**, and a resumed
chain stays pinned to the unit's config generation. **`disk.append`** (the export kind's file sink,
§11.11 R4): `{dest_key, bytes} → {written, rotated}`, may pend, write-behind class, on the bounded disk
lane; the host maps the key to a path and applies its rotation config. A plane's trust keys come from
its plane-kind tail; the old hot declaration never grows.

**11.13 Mechanism rules every kind obeys (ARCHITECT rulings 2026-09-27/28).** The kind-specific
validator rules live beside their shapes in `busbar-contract/src/abi/<kind>/`, each with a RED test
and a distinct message per arm; what follows binds every kind.
- **Answers are validated where their shape lives.** Each kind's out-validation is a pure
  `check_<op>(out, caps) -> Result<(), Fault>` beside its shapes (u64 arithmetic, no statics); the
  dispatcher calls it and no host re-implements it. `needed_bytes` ≤ `u32::MAX` and every other
  `needed_*` ≤ that kind's hard maximum; an absent span has length 0; a count above 0 with a null
  pointer is FAULT; an "exactly one of" bitfield with 0 or 2+ bits is FAULT; counts are checked against
  their caps with checked arithmetic; every list element is checked; an unknown enum or flag value is
  FAULT. Shared helpers live in `abi/mechanism/check.rs`.
- **The short-buffer answer (M-SB), stated once in `abi/mechanism` and cited by every kind.** Request-
  path results are written into HOST buffers the `in` names (pointer + capacity). "Your buffer is too
  small" is FAILED with every `needed_*` at its full size, at least one above its capacity, and
  nothing applied or written; the host re-calls ONCE on the same ticket with at least `needed_*`; a
  second short answer is FAULT. `needed_*` on any other outcome is FAULT; FAILED with every
  `needed_*` fitting is FAULT; REFUSED never carries `needed`. The re-call is side-effect-free: the
  plugin checks capacity BEFORE acting; an op that cannot know its size first (bind, accept) gets a
  host buffer at the kind's declared maximum and has no short path — an over-cap length there is
  FAULT. A ticketless short answer is re-called only through an explicit `recall(prev)` the dispatcher
  enforces once.
- **Hard maxima.** Plane and transport: unit counts ≤ 64; fields, records, routes and claims ≤ 1024
  each; frame pieces ≤ 4096; bytes ≤ `u32::MAX`. Hook serve: at most 64 headers out. Auth: see §6.
- **Secret-bearing answers are always secret on the host side;** no plugin sets a "sensitive" flag.
- **The dispatcher (M1).** An instance never crosses after `close`; `close` is refused while units are
  in flight; start, resume or cancel on a closed instance is FAULT with no crossing. Every slice built
  from a plugin-reported length is capped and validated before it is formed, diagnostics and labels
  included. Every crossing, ticketless included, is watched by the watchdog. No plugin code (`dlclose`
  included) runs under a host lock. `Kind::check` answers `Result<(), Fault>` and a fault is logged at
  warn with plugin, kind and slot, never the payload. Dropping a pending reply cancels every queued op
  on its ticket — a client drop (ARCHITECT, 2026-09-28).
- **One kind-neutral SDK lifecycle (KIND-SHARE, ARCHITECT ruling 2026-09-30).** The SDK's door holds
  the generic lifecycle slots once; each kind states only its own; one `KindAxis` (associated types)
  and a root `RootAxis<K>` serve every kind; the SDK writes the out pointers; a published arena lives
  until its generation retires; releasing an unknown lease is REFUSED; the drive, validate and cancel
  words are per-kind constants. KIND-SHARE's lifecycle module is the one lease and error helper; a
  kind's local copy is deleted when it is ported.
- **Pre-tag layout edits.** R9's clarification (a v1 edit before the tag regenerates the layout golden
  and bumps nothing) applies to every kind's unreleased 1.6.0 version, not only the plane's
  (ARCHITECT, 2026-09-29).
- **Test doors.** A dropped-in door in a test comes from a built cdylib that is `dlopen`ed, never from a
  linked dev-dependency with the export feature on.

## The vocabulary (get this right or you will design the wrong thing)

**7 plugin kinds** (#3): `store`, `secret`, `auth`, `hook`, `export`, **`plane`**, **`transport`**.
- `auth` is ONE kind. Inbound-verify and the outbound per-request auth-fields call (the auth object, THE DESIGN §6) are two *operations* of it. Direction is a
  usage mode, not a kind. There is no "egress-auth" kind.
- `transport` is ONE kind, bidirectional: carriers and framers. EVERY plugin of any kind declares its connection needs as
  `(transport, auth)` per direction, and the kernel instantiates them through `busbar-core-connector`. TLS is core-only,
  inside the connector — never a transport (THE DESIGN §5).
- **NOT kinds:** `control` (admin, oauth2 and the connector are cleanliness crates, THE DESIGN §8), `dialect` (lives inside a plane),
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

**7 kind ABIs, one shared mechanism** (THE DESIGN §11, OWNER-LOCKED 2026-09-27): plugins speak the
memory ABI only. Each kind has its own operations, shapes and version; all seven share one table-of-
function-pointers mechanism, Ready/not-ready results and the #85 envelope. JSON is only a payload blob.

~~**2 ABI lanes, split by heat** (#30):~~
~~- **HOT / POD** — `plane` + `transport`. In-memory, `repr(C)`, sub-microsecond.~~
~~- **COLD / JSON** — `store`, `secret`, `auth`, `hook`, `export`.~~

~~Both lanes exist on the one seam, but **each kind is bound to exactly ONE of them, chosen by heat — a plugin uses the tier matched to its heat, NOT both (#30)**; the lane is a **dispatch-cost** decision, not a second contract, and there is ONE contract per kind.~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.1.
Every plugin can be **compiled in OR dropped into `plugins/`** — same contract, same loading path — and communicates ONLY over the ABI. Those are the only two requirements; there is no third (#2).

**Rejected, do not resurrect:** D36 (dialect as a plugin kind / per-dialect crates) and D37 (a
`control` plugin kind). If a stale checklist reports these as "todo", it is wrong — ignore it.

## The laws in one breath

**Law 0:** every plugin is isolated from everything except through its ABI to core; core is isolated
to communicating over that ABI and knowing what **kind** a plugin is. That's it. Neither side ever
needs more. If either appears to need more, the design is wrong, not the invariant.

Everything else is a corollary: core has zero instance logic (1); no lateral plugin edges (2); a
plugin asks and core provides (3); one crate = one plugin = one plane (4); dialects are internal (5);
billing is declared once and priced generically (6); every plugin is off until config uses
it, no exceptions (7). Full text in Part 1; the kernel<>plugins design is THE DESIGN above.

## What "done" means

> **OWNER RULING 2026-09-23.** *"So what done is, is THAT. Not some script, not anything else."*
> *"How you personally prove THAT is on you. A `verify-1.6.0-done.sh`, sure — that's YOU, I don't care."*
>
> **DONE IS THE BLOCKQUOTE AT THE TOP OF PART 0.** Nothing else is the definition. No script, gate,
> ratchet, group count or checklist is the acceptance criterion — every one of them is an
> INSTRUMENT the architect built to prove the statement, and an instrument that disagrees with the
> statement is a broken instrument, not a new requirement.
>
> This inverts what had drifted into place. The done-oracle script had become the thing being chased,
> which is how a naming ratchet ended up costing more than the re-architecture it was supposed to
> witness. The script serves the statement; it does not define it.

**The statement decomposes into exactly four falsifiable claims.** These are what the architect must
prove, and each one names the failure that would refute it:

| # | Claim (from the ratified statement) | Refuted by |
|---|---|---|
| **C1** | Core is a thin engine that knows nothing about any specific protocol. | Core naming any plane type; or adding a dialect to a plane requiring ANY change to a core file. |
| **C2** | Every plugin can be compiled in OR dropped in over the same contract and same loading path, and talks to core only over the ABI. | Any of the 7 kinds lacking a both-ways proof (per kind: ONE conformance suite running the shipped compiled-in build and the dropped-in build through the same table, THE DESIGN §11.4); any lateral plugin-to-plugin edge; any kind whose two folds differ. |
| **C3** | LLM-only 1.6.0 is byte-identical to published 1.5.5. | One unexplained cell in the oracle diff against the real 1.5.5 binary. |
| **C4** | Money is a view: `money = f(ledger, ratecard)`, nothing stores a dollar. | Any stored price; any float; any money finding that cannot name ledger-or-ratecard as the wrong one. |

### MEASURED STATUS OF THE FOUR CLAIMS — 2026-09-23

The claims are the release's definition of done. Three of the four have now been MEASURED rather
than asserted, and two are **refuted**. This table is the honest state; the refutations are not
reasons to weaken a claim, they are the work.

| | status | the measurement |
|---|---|---|
| **C1** | **UNMEASURED over 5 of its 7 kinds** | `INSTANCE_VOCAB_KINDS = ["plane","transport"]` (`kind_isolation/matrix.rs:116`). Core carries no cell on the store, secret, auth, hook or export axis. A counter-example is live in core: `EXPORT_MODULES` (`config/sections.rs:435`) is a closed list of export instance names and `config/mod.rs:1983` refuses every name outside it. **Every C1 green on record is a statement about planes and transports only.** |
| **C2** | **REFUTED for the `export` kind** | `config/mod.rs:1983` hard-errors at boot on any export module name outside the four built-ins, so a dropped-in export plugin cannot be NAMED in a config file; `open_export` has zero callers against four positive controls. The two folds are not the same contract. Same root cause as C1's hole. |
| **C3** | **REFUTED — 16 diverging cells, 12 of them product** | LLM-only build recorded against the published 1.5.5 golden: `owed 916 · diverging 16 · --strict rc=1`. C3's own criterion is one unexplained cell. Both byte-neutrality claims in `crates/busbar/Cargo.toml` (`:263` for `root-llm`, `:309` for `root-admin`) are **false** — a 2×2 isolation shows each moves cells its own comment says it does not. |
| **C4** | **the instruments cannot currently refute it** | The reconciliation compares an empty book to an empty book and passes; the rollback detector is declared and never constructed; the books-balance verifier wraps in release. Those are not a C4 verdict — they are the reason no C4 verdict is available yet. |

**The honest reading:** C3 and C2 are refuted, C1 is unmeasured over most of its surface, and C4 is
unmeasurable until its instruments are repaired. None of that changes what the claims should say.
It changes what "done" costs, and it is why Phase 1 (arm the instruments) precedes Phase 2 (money)
and Phase 3 (C3) in the execution order rather than running beside them.

**One refutation is already ruled on.** Ruling 8 — *"the 1.5.5 under-billing is CORRECTED in 1.6.0,
with no customer restatement; C4 wins over C3 on the 42 affected cells"* — is the precedent for a
cell where 1.5.5's bytes are the wrong ones. At least one of the 16 is of that shape
(`billing|key-usage|after-upstream-down`, whose own `why` says the new answer is correct), so it
needs a signed exception rather than a fix. **The exception was never written**, which is the
actual defect there.

**C1's test is the sharp one and it is nearly free to run:** add a dialect, and `git diff --stat` must
show zero files changed under core. That single command falsifies or confirms the entire premise of
the release, which is more than the done-oracle script can say.

The instruments below exist to serve those four claims. Where an instrument is red on something that
bears on none of them, it is reporting a defect in itself.

### The instruments (evidence, not definition)

Dev-green on **one SHA**, with nothing outstanding or niggling:

1. `scripts/verify-1.6.0-done.sh` exits 0 across all of its groups (`DONE_GROUPS_DECLARED`, 24 today) — full run, never `--fast`
   (exit 3 is PROVISIONAL, not spendable), every bless/repoint env var empty.
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

> *Absorbed verbatim from `VISION-1.6.0.md`, which this document replaced and DELETED (`49ab4aca2`) — that name is history, not a path. Highest authority in this document.*


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
   **Every layer hard-codes a vocabulary, never an instance (OWNER 2026-09-30):** core hard-codes the
   7 kinds; a transport hard-codes the auth points (THE DESIGN §6, "Auth points and guest lists"); an auth hard-codes
   the neutral message shapes (field lines, target, body, frame, peer facts); a plane names transport
   claims and auth styles, resolved at boot. Naming an instance across a layer boundary is a defect.

2. **No lateral edges.** A plugin never names, imports, or talks to another plugin — same kind or
   different kind. Plane↔plane, dialect↔dialect, plugin↔plugin: forbidden. **Core orchestrates
   everything**; all coordination flows through core over the ABI.

3. **Plane asks, core provides.** A plane declares a *need* (e.g. "I want an HTTP session"). **Core**
   creates it from a transport and hands it over. A plane never grabs a transport or another plugin
   itself. The same holds for every plugin of every kind that needs an external connection (THE DESIGN §5).

4. **1 crate = 1 plugin = 1 plane, self-contained and droppable.** Everything a plane needs lives in
   its one crate. Drop one crate into the plugins folder → core now knows about LLMs, or MCP, or a
   VPN, or whatever is next. No cross-crate sprawl to make one plugin work.

5. **Dialects are internal to their plane — NOT a plugin kind.** One plane owns one IR; that IR *is*
   the plane. One plane speaks 1+ dialects. Dialects live **inside the plane crate** as clean code
   (e.g. `src/dialects/openai.rs`, `src/dialects/anthropic.rs`). Adding a dialect (e.g. `mcpv2`) =
   add a file in that plane crate; the plane's shape does not change and **core does not change at
   all**. Whether a plane uses an internal trait to organize its dialects is **that plane's own,
   standalone decision** — never imposed by core or the contract. **Pass-through is still an IR**
   (owner, 2026-09-02: *"pass-through ≠ no IR"*): a plane that relays bytes unchanged — same-dialect
   streaming, a media relay — still runs its reader, and that reader is the one place the plane's
   usage and audit facts come from. *"An identity transform is still a tap."*

6. **Billing is declared once and priced generically.** A plane declares its **units** (tokens,
   streams, audio-seconds, tool-calls, …) once. Core captures the quantities and prices them against
   the **rate card the user registered**. Units rarely change — a frozen schema — which is what keeps
   the money path byte-identical to 1.5.5.

7. **Config-gated loading — every plugin is off until its config verb is used.** Core loads a plugin
   **iff** its configuration section is present. No verb configured → that plugin is never loaded.
   This holds for **all** kinds, not just planes: don't configure a SQL store → it is never loaded;
   don't configure the plane verbs (`pools` = LLM, `tools` = MCP, `agents` = A2A, `streams` = streaming, `decisions` = decisions)
   → those planes are never loaded. This is the *mechanism* behind "LLM-only ≡ 1.5.5": with only
   `pools` configured, only the LLM plane loads and the bytes are identical to 1.5.5; add `tools` /
   `agents` / `streams` and the MCP / A2A / streams planes load — purely additive, nothing else
   changes. A plugin that loads (or costs anything) without its verb configured is a bug. There are
   no exceptions: a plugin loads iff config USES it, env and file secrets and the memory store
   included, and `store:` is required (THE DESIGN §2, §4).

## What this means for the gates
The purity gates (`plane-purity`, `kind-isolation`) exist to **enforce Laws 1 and 2**: no plugin
instance named in core/neutral crates, no lateral plugin naming. They are **servants of the vision,
not the vision**. Consequences:
- A plane naming its **own** dialects/vendors is correct (Law 5) — it is internal. A gate that reds
  on that is **scoped wrong**, and the fix is the gate's scope, not the code.
- `plane-grep-gate` and `plane-noun-gate` are **report-only debt meters**, explicitly **excluded**
  from the done-oracle (`verify-1.6.0-done.sh`). They do **not** gate the
  release and must never drive architecture (e.g. splitting a plane into per-dialect crates to make
  a substring count hit zero — that violates Laws 4 and 5).
- **When an instrument must choose, it false-fails.** Owner, 2026-09-09: *"I'd rather have it
  false-fail than not."* Between a false RED and a false GREEN, a gate takes the false RED; where two
  scanners disagree, the higher count wins.
- **A capability that is never constructed does not ship.** *"Its tests prove the code works; they
  prove nothing about whether it runs"* (architect law, 2026-09-22; `xtask/src/gates/unconstructed.rs`,
  `qa/unconstructed.toml`). A built type or verb with no production construction site is either wired
  or deleted before the cut.
- **An unruled edge never ships.** In the kind-isolation ledger, `allowed` and `tcb` are readings of
  the architecture, never opinions a row may grant itself; an edge the architecture does not rule on
  carries its written question to the owner. The ship check admits only the classes the
  architecture allows — `tcb`, `not-allowed` and every unruled edge are refused, because the
  criterion for a tag is not "no worse than the last commit".

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
  benefit** (nothing reds because of them). It is finished or excised before DEV-GREEN (Definition of Done, item 5).
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

**The oracle's scope is 1.5.5 parity, and no more.** No 1.5.5 golden can exist for a post-1.5.5
plane, so new-plane gaps are never closed by adding oracle cells: plane money is witnessed by the
conformance rigs (the meter-row, card-epoch and class-price legs) and by the ONE money function's own
test. Never cite oracle-green as evidence about plane money. The corpus IS owed cells for surfaces that
existed in 1.5.5 and lost coverage (the export sinks).

**Every release records its own golden** (OWNER 2026-09-22). `golden/1.5.5` exists; `golden/1.6.0` is
recorded at the 1.6.0 cut, from the RELEASE build at the release SHA, never from a dev tree. A cell
with no prior golden reports UNBASELINED, never PASS: a gap and a failure must never be the same
output, and neither may a gap and a success. `accepted-differences` stays cumulative and signed, and
is read whole at each cut; a money value that moved in four consecutive releases is a finding even if
every move was signed.

## Definition of Done — the checklist (owner-set; do not lose to compaction)
"Done" is **dev-green 1.6.0 with nothing outstanding, deferred, or niggling** — the point where the
architect can honestly say *"there is nothing left to do; it is perfection until users test it."*
Concretely, ALL of:
1. `scripts/verify-1.6.0-done.sh` exits 0 on one SHA, and dev CI is green on it.
2. **Construction standing-reds are EMPTY** — `ship-ready` green, not merely `--posture`-tolerated.
   The LLM-engine rebuild is done (no 1117-line request-path fn; terminal doors only in the Audit
   step; the price named only where the card lives; one pick site; ports-only tests; holds clean).
   **The hard clause:** every `Family::Neutral` crate — the kernel and its 8 workflow crates, `busbar-contract`,
   `busbar-plugin-loader`, `busbar-core-admin`, `busbar-core-oauth2`, `busbar-core-connector`, **and the
   composition root** (the 15-crate repo, §9) — names
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
   `Kind::Dialect` remnant), docs + version bump landed, changelog complete. The owner's LOC signal
   holds: excluding the new planes, 1.6.0 production LOC is the same as 1.5.5 or less ("if the same app
   takes 2x the code something is wrong"); growth sits in three named buckets (1.5.5 parity, planes,
   the plugin seam) and any fourth owes a reason. One counter: `cargo xtask loc --ref v1.5.5`. A
   duplicate that encodes a security or money property outranks a bigger one; a parity test is not a
   fix; legacy is deleted, never built beside.
6. Compatibility: zero config changes beyond the signed ones; the admin API a superset of 1.5.5's; a
   zero-allocation hot path. Performance has no fixed numbers (OWNER 2026-09-30, §11.9): throughput as
   high as possible with 2× 1.5.5 as the floor, measured in the PERF phase that follows the first
   DEV-GREEN (order: CODE → DEV-GREEN → PERF → fixes → DEV-GREEN again).

## How "done" is proven
- Quality is proven by the **byte-identity oracle** (money path vs the 1.5.5 golden), the crate's own
  **tests**, **clippy**, and **`/codeaudit` looped to two consecutive zero-finding reports** — not by
  a substring grep. A crate that owns vendor names (a plane) is proven clean by these, not by the
  meter that (correctly) does not scan it.
- The release is done when **`scripts/verify-1.6.0-done.sh` exits 0** (its groups are the real
  oracle: build, plane-purity, byte-identity/parity, config-stability, no-deferral, conformance,
  design-bindings, changelog, plane-delete) and dev CI is green.

---

## LAW 8 — A MEASUREMENT MUST STATE ITS DENOMINATOR, AND PROVE IT PARTITIONS

Law 0 says an instrument that cannot produce a NO is not a check. Law 8 is its other half, and it
was learned the expensive way — twice in one day, once by the code and once by the audit of it.

**A count is not a measurement until you can say what it is a count OF, and prove nothing fell
outside.** Every false green this release has produced is one of three shapes:

1. **The hand-written denominator.** An instrument checks a list somebody typed, and nothing forces
   the list to keep up with the thing it enumerates. `money-invariants` names 8 record types where
   `records.rs` defines 17. `instance-noun-neutrality` holds 25 nouns and not one of them is a
   dialect, so it cannot see `DEFAULT_PROTOCOL`. The oracle's admin corpus is a fixture frozen at
   the 1.5.5 op set, so eleven new served paths have no cell and no mechanism that could ever give
   them one. Each gate is *correct about what it was told to look at*, and silent about the rest.

2. **The absent floor.** `--strict` returns success on one owed cell of 2,318 because the only
   check is `owed.is_empty()`. Lesser gates in the same tree declare `DENOMINATOR_FLOOR = 1_700`,
   `SCAN_FLOOR = 200`, `BINDING_FLOOR = 40`. A denominator with no floor is a denominator that can
   be reduced to one without anybody noticing.

3. **The partition that was never checked.** A sweep assigned all 3,915 tracked files to ten
   slices by path prefix and called that a coverage proof. Slice 2 took `a..busbar-k`, slice 3 took
   `busbar-l..z`, and `busbar-k` < `busbar-kernel` < `busbar-l` — so the nine kernel crates, 574
   files and 242,730 lines of CORE, fell in neither and were never examined. The file count was
   right. The scope was not. **Proving every element has an owner is not the same statement as
   proving the owners' scopes cover every element**, and the second is the one that matters.

**The rule.** An instrument declares the set it measures over and a floor beneath which its own
result is a refusal rather than a pass. A census reports the LIST it scanned, not the count, and
coverage is computed as the union of those lists reconciled against the whole — AFTER the work,
never before. Where a roster of instances must exist, it is derived from the instances' own
declarations; a roster maintained by hand is a defect with a date on it.

**A name is not a thing.** Six wrong conclusions in this release came from grepping a name: a
`#[cfg]` one line above the `pub mod` it gated; a path that had been renamed since the tag, where
`git show <ref>:<missing>` prints nothing and `grep -c` reports `0`; a type name where the rule
barred a concept; `prove_red` where the tree's own helper is `prove_rows_red`; a field doc on one
struct used to indict a writer on another. And `design_bindings/tables.rs` carries 409 prose
strings naming functions, so any census keyed on names reads them as references and scores dead
code live — which is precisely how an unwired money backstop stayed invisible. **Run a positive
control before believing a zero: search for something you know is there, and show it.**

**Every gate owes a positive control.** Keep one known violation out of the instrument's reach and
check the instrument against it; a gate that cannot be shown failing is not evidence. Cite a defect,
never an unenumerated count.

### Law 9 — arm at today's number

An instrument that blocks REGRESSION is worth having on the day it is written, even while the debt
it measures still stands. Holding a gate switched off until its count reaches zero is how this
release built a dependency cycle: Wave 0 ("make the instruments able to fail") could not land
because its ceilings only reach zero in Wave 5, and Wave 6 rewrites the corpus Wave 0's gates read.

**The rule.** A new or newly-armed instrument pins its ceiling at TODAY'S MEASURED VALUE and
refuses every rise from that moment. The drain runs behind it, ratcheting the ceiling down. An
instrument's proof of life is that it CAN fail and that it RUNS — never that its number is zero.

This is how every ratchet in this tree already works. Stating it as a law is what dissolves the
cycle: item 6 splits into "wire the gates into CI" (a set-equality check about registration,
landable immediately) and "make the gates green" (content, which waits for the tree to settle).

### Law 10 — a forgiveness whose premise is never checked is a blindfold

The oracle's register may forgive a difference, and every entry states WHY. That `why` is a
premise about the build under test, and nothing evaluates it.

Found live: entry **F-011b** forgives the served `openapi.json` listing the MCP and A2A endpoints,
on the stated grounds that *"openapi.json describes the MCP and A2A endpoints."* The document is
`include_bytes!("openapi.json.gz")` — compile-time embedded and entirely feature-independent — so
in a build with those planes compiled OUT, the binary advertises a surface it cannot serve, and the
very cell whose contract is *"the document must list only the 1.5.5 admin surface"* is scored
`accepted` rather than `diverging`.

**The rule.** An entry's premise is written as a condition the runner evaluates against the build
in front of it. A premise that cannot be evaluated is not a reason; it is a wish, and the entry is
refused. This is Law 0 applied to the register rather than to a gate: a forgiveness that cannot
turn back into a refusal is not a forgiveness.

### THE MEASUREMENT HOLE UNDER C1 AND C2

Recorded here rather than in the plan, because it is a statement about what the claims MEAN.

C1 — *"core names no instance"* — is asserted over all **7 plugin kinds** and measured over **2**.
`xtask/src/gates/kind_isolation/matrix.rs:116` reads
`const INSTANCE_VOCAB_KINDS: &[&str] = &["plane", "transport"];`, and `:1193` skips every kind
outside it. Core carries no `[[cell]]` on the store, secret, auth, hook or export axis at all.

The counter-example is in core: `crates/busbar-kernel/src/config/sections.rs:435` defines
`EXPORT_MODULES`, **a closed list of export-plugin instance names inside the engine**, and
`crates/busbar-kernel/src/config/mod.rs:1983` refuses at boot any `export.<name>.module` outside
it. Same shape at `config/mod.rs:820` (`RETIRED_STORE_MODULES_1_5_3`), `:824`
(`STORE_MODULE_VALKEY`), and `config/migrate.rs:905`.

**This is one hole under two claims.** It breaches C1 directly. It also breaches **C2**: if core
refuses every export module name it does not already know, a dropped-in export plugin cannot be
named in a config file, so for the `export` kind the compiled-in fold and the dropped-in fold are
NOT the same contract — which is the one universal rule a plugin has. Neither of the two
instruments that claim to enforce C1 can see it, and `instance-noun-neutrality`'s export/secret/hook
tokens are the fixture crate names (`export_example_plugin`), not the real instance vocabulary.

Arming the five missing kind axes is a Phase 1 item. Until it lands, **every C1 green on record is
a statement about planes and transports only.**

# PART 2 — THE 85 LOCKED DECISIONS

> *Absorbed verbatim from `DECISIONS.md`, which this document replaced and DELETED (`49ab4aca2`) — that name is history, not a path. Row numbers are cited from source comments, gate ledgers and commit messages — they are permanent. Cite a row; never re-litigate it.*


Rule: a decision here is LAW and states the CURRENT truth — facts only. When a decision changes, its
row is rewritten to the new truth; rows never carry an override trail ("ignore X, do Y", "AMENDS",
"CANCELLED", dated rulings). If it has an enforcing gate, drift turns the gate RED — it cannot be
re-opened in conversation. If "Gate" says TODO, adding that gate is itself a task. Never re-litigate a
row here; cite it. Only Part 1 (the Laws) and Part 3 (the plane seam) outrank this Part, and both
are IN this file — nothing outside it does.

| # | Decision (LAW) | Enforcing gate |
|---|----------------|----------------|
| 1 | **Architecture = core + plugins.** Core is a thin engine running ONE uniform per-unit governance workflow (Authenticate·Verify·Approve·Admit·Route·Meter·Audit) that every plane's data passes through. Core names ZERO plane types. The kernel IS that loop and names no plugin, and every plane gets every core capability — breaker, hooks, metrics, audit, outbound auth (owner 2026-09-02: *"LLM == MCP == A2A — just different protocols not different pathway through engine at all"*; THE DESIGN §1). | plane-purity (reverse), plane-abi-neutrality grep, teller-steps, capability-equality + plane-isomorphism tests |
| 2 | **A PLUGIN IS A PLUGIN — exactly TWO requirements, every kind (plane included):** (1) compiled-in OR dropped-in (same contract, one loading path); (2) communicates ONLY over the ABI — its kind's memory ABI (THE DESIGN §11.1). No third requirement. **Compiled-in = dropped-in through the same table (THE DESIGN §11.4):** a compiled-in plugin exports the same door and is called through the same table as a dropped-in one; the kernel never holds a plugin crate's Rust types or calls its Rust functions (owner 2026-09-27: *"compiled or dropped in is just a convenience for customer; NOTHING CHANGES about the plugin itself and how it works."*). **A PLUGIN = A 3rd PARTY — ACCEPTANCE TEST:** a plugin SELF-REGISTERS via the one door macro `busbar_contract::export_plugin!` and TESTS ITSELF; the kernel never tests it and never names it — not in code and NOT in its own tests. The grep for a concrete instance noun stays neutral INCLUDING under `tests/`: if the kernel names or tests a specific plugin by name, it has stopped treating it as a 3rd party and the row is violated. **WITNESSES (THE DESIGN §2):** each plugin's own `tests/conformance.rs` links it AND loads its own cdylib through the real loader, compares the folds and keeps its RED arms; each kind has ONE conformance suite that runs the SHIPPED compiled-in build and the dropped-in build through the same table (THE DESIGN §11.4). ~~`busbar-plugin-loader` keeps one both-ways witness per kind, on a REAL plugin, never a fixture (the example and test plugins are gone).~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.4: measured 2026-09-27, only export reaches its compiled-in plugins through the ABI (store, hook, secret, auth, transport and plane bypass it) and the both-ways tests mostly compare the Rust API against the ABI. The auth kind's witness is `auth-oidc`; before it the auth kind had no both-ways proof at any tag, v1.5.5 included — the old "token-auth cdylib proof" named no code (archaeology, 2026-09-23). | kind-isolation, instance-noun-neutrality, construction:ports-only-tests, one conformance suite per kind running the shipped compiled-in build and the dropped-in build through the same table (THE DESIGN §11.4) ~~one both-ways witness per kind in `crates/plugin-loader/src/tests/*_conformance_tests.rs` on a real plugin~~; each plugin's own `tests/conformance.rs` |
| 3 | **Plugin kinds (7):** store, secret, auth, hook, export, PLANE, TRANSPORT. A kind = a capability core brokers by key, swappable (compiled-in OR dropped-in over the ABI), of which core names no concrete instance. **Direction (inbound/outbound) is a usage mode, never a kind boundary.** TRANSPORT is one kind, bidirectional: a plane declares a transport need and, if core lacks that carrier, you install the transport plugin too — the transport plugins are carriers (tcp, stdio) and framers (http — claiming http, https and sse — ws, and grpc, its own transport, OWNER 2026-09-29); one entry per plugin, a duplicate claim fails boot, no transport names another; TLS is core-only connection security inside `busbar-core-connector`, never a transport and never over the ABI (THE DESIGN §5). AUTH is ONE kind: inbound-verify and the outbound per-request auth-fields call (the auth object, THE DESIGN §6) are two OPERATIONS of the auth kind, not two kinds — there is NO separate "egress-auth" kind (the code's `auth`/`egress-auth` split is an ABI detail inside one kind). Every plugin of any kind declares its needs as (transport, auth) per direction — inbound {transport=X, auth=Y}, outbound {transport=A, auth=B}. NOT kinds: control (admin, oauth2 and the connector = cleanliness crates, #5), dialect (inside a plane, #4), unit (core's governance workflow). Instances, each in its own repo: THE DESIGN §9. The four 1.5.5 export sinks are real both-ways export plugins over the export kind's memory ABI (~~COLD/JSON ABI~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.1), behaviour byte-identical to 1.5.5, oracle-gated on the export/metrics path (OWNER RULING 2026-09-18). | kind-isolation:registry (7 kinds) |
| 4 | **A DIALECT is a thing INSIDE a plane** (llm 6, mcp 1, a2a 1, streaming N). It is NOT a plugin and NOT a kind. No per-dialect crates, no Dialect trait/kind. | kind-isolation:truths (dialect kind ⇒ RED) |
| 5 | **admin, oauth2 and the connector are NOT plugins.** They are the three compiled-in cleanliness crates, one-way dep on core; admin and oauth2 are off the hot path, `busbar-core-connector` is on it (THE DESIGN §8). There is no "control" plugin kind. | kind-isolation:registry/truths |
| 6 | **One crate per plane** `busbar-plane-<x>`, pure. ALL plane logic — dialects, codecs, modes — folds INTO that one crate; there is NO separate `busbar-*-codec` crate (#39). A plane opens no socket; all wire I/O is the transport plugin's (#7/#40). The plane crate's dep closure names no kernel/core type (#40). | construction loc/surface ceilings; no busbar-*-codec crate |
| 7 | **A plane opens NO socket.** It declares transport needs as data at registration and asks core for a transport; No plugin of any kind opens a socket: dialing and framing are the transport plugins', pools and TLS are `busbar-core-connector`'s, the allow-list, pin and breaker are the kernel's (THE DESIGN §5). Hot read/write = POD-by-pointer, zero-alloc, zero per-token host crossings. | source-denylist (hyper/reqwest/tokio-net out of plane closure) — TODO arm; perf/alloc gate |
| 8 | **Broker law:** plugins never talk to each other. Each declares needs+capabilities; core brokers by capability key (registry lookup, core names no concrete plugin). Coupling only ever points down (at core/contract). | plane-abi-neutrality, kind-isolation:deps |
| 9 | **Byte-identity = USER-OBSERVABLE contract, not internal-structure.** A 1.5.5 user upgrades to 1.6.0 and notices nothing. Internals may be rewritten freely; the oracle proves no user-visible byte moved. **What "identical" is measured against (PB-0, the master parity rule, 2026-09-04/05):** every row of every 1.5.5 inventory file (`qa/evidence/inventory/1.5.5-*.md`) is a parity binding and an oracle cell, whether or not any other text restates it — the 1.5.5 behaviour it cites is reproduced byte for byte on every 1.5.5-reachable surface; a behaviour absent from a restatement binds nothing looser; where a restatement paraphrases a row imprecisely, the row wins; and a stricter or different rule written elsewhere is internal, while the row is what a 1.5.5 user observes. **The one standing exception is maximum spec compliance** (owner, 2026-09-04): where the published 1.5.5 bytes deviate from a provider's own published spec, the spec wins, and each case is registered as `improvement` in `accepted-differences.json` with owner sign-off (first cases: Bedrock text blocks without a `contentBlockStart` frame, the Responses door's lifecycle frames, the required members added on every dialect, every Responses-door stream request actually streamed). Named gap against the spec, kept: the Anthropic `ping` frame stays. Owner-signed specifics: `GET /admin/openapi.json`'s `info.version` reports the running binary's version; every other byte of that document stays 1.5.5's except description leaves registered as owner-signed factual corrections (PB-75 as amended by the owner: *"verbatim EXCEPT registered factual corrections"* — the register's `description_corrections`, string leaves only). | shadow-oracle diff vs golden/1.5.5 (NEVER waived); every max-spec difference has a signed register entry; every inventory row maps to a cell |
| 10 | **The oracle's sole job:** prove no user-visible byte changed. A RED cell is a QUESTION, not a failure. Agent-laziness is root-caused and fixed without owner involvement. Every genuine RED cell that has a 1.5.5 golden is PARKED for owner sign-off (cell + exact diff + root-cause + recommendation) — never silently self-fixed — while the run continues on other fronts. Money-path bytes are sacred. The register holds each deliberate difference as one of three kinds, every entry owner-signed: `improvement`, `breaking` (each named in the CHANGELOG, owner 2026-09-04), or **`additive`** — owner, 2026-09-07: *"key-list and view GROWTH is a new feature and not a break"*, machine-checked rather than judged: the candidate body is a JSON superset of the golden at every path the golden names (arrays: the golden a prefix or equal), headers a superset with none changed or removed, and status is never taken; its siblings `text_list_growth` (a backticked list in a message grows by appended items only) and `new_route` (where the 1.5.5 golden answered 404 for a route it did not have, an additive route may take status, headers and body) are checked the same way. Maximum spec compliance (#9) is the only standing class of `improvement`; every other entry is signed one at a time. | shadow-oracle; parked-divergence log; accept-register requires owner sign-off; `changelog_register` (every `breaking` entry in the CHANGELOG) |
| 11 | **1.6.0 ships TWO distributions, one contract; both-ways is REQUIRED for every plugin kind incl. PLANE.** Every plugin is compiled-in OR dropped-in over the same contract and one loading path (#2). DEFAULT distribution = everything compiled in; BARE-BONES = core + drop-in plugins. The folder-drop loader for every kind (planes included) is in the cut. **Compiled-in vs dropped-in is a BUILD/packaging property, NOT a development-coupling one:** every plugin is developed INDEPENDENTLY (exactly as in 1.5.5 — no plugin's source depends on the kernel's internals to be built), the DEFAULT build simply compiles them in, and every plugin lives in its own repo IN 1.6.0 (#39, §9; extraction is TODO phase P5). | build gate (both distributions green) + per-kind drop-in conformance rig — TODO arm bare-bones + drop-in rig |
| 12 | **1.6.0 = 1.5.5 + MCP + A2A + STREAMING + DECISIONS(jev).** The added planes bring the roster to 5 (llm/mcp/a2a/streaming/decisions, #48); live realtime voice is ONE capability the streaming plane carries, not its name (streaming does more than voice). New planes are additive, config-reached (add tools/agents/streams/decisions to config); they never touch the existing 1.5.5 experience. The internal re-architecture IS 1.6.0 (else it's just 1.5.5). | conformance (mcp/a2a/streaming/decisions rigs) + oracle (1.5.5 unchanged) |
| 13 | **Marketing = vision; docs = truth.** A vision↔truth delta is a decision (agree/disagree → new row here), not an auto-fix. Owner updates marketing to fact-based AFTER code lands. | (process) |
| 14 | **THE AUTHORITATIVE DOC IS THIS FILE, `docs/design/BUSBAR-1.6.0.md`, AND NOTHING ELSE.** The two files this row used to name alongside it — `VISION-1.6.0.md` and `1.6.0-plane-extraction-LOCKED.md`, together with `DECISIONS.md`, `1.6.0-PLAN.md` and `1.6.0-plane-abi-taxonomy.md` — were absorbed VERBATIM into Parts 1/3/2/5/4 and DELETED in `49ab4aca2`. They are Parts, not files: a citation to any of those five filenames is a BROKEN citation and must be repointed at the Part that holds it, never chased. Authority is the order in this file's header: Part 1 > Part 3 > Part 2 > Part 5. Every other design doc is reconciled to this file or deleted. No stale line may survive for an agent to resurrect — including a pointer to a file that no longer exists. | doc-reconciliation pass; no live sentence in `docs/design/` names a deleted predecessor as authoritative |
| 15 | **Banned words:** defer / 1.6.x / later / "out of scope for 1.6.0". 1.6.0-or-bust. Feature-need changes come to owner with a real case; agent-laziness = fix the root. | (process) |
| 16 | ~~**Worst-case ship date: Wed 2026-10-08 17:00 PDT.**~~ **VOID — owner ruling 10 (2026-09-23): *"forget a date, i want a plan for DONE"*. Three mutually inconsistent dates survived in this file (2026-10-08 twice, 2026-09-25 once); all three are void. The plan is ordered by dependency.** Moves only on a named MAJOR EVENT (Commit-C non-decomposable + divergence cascade; systemic HIGH reopening money path; fleet outage). | Part 5 "Dates" (this file) — same floor, restated there; drift between the two is the gate |
| 17 | **One feature per plane, no `root-*`.** The per-plane compile knob is exactly `plane-<x>` (pull the plane crate + enable core's plane edge). END STATE default = `["auth-admin-tokens","hook-ranking","plane-llm","plane-mcp","plane-a2a","plane-streaming","plane-decisions"]`. The whole `root-*` family is gone (`teller-waist` is unconditional; the tower dep folds where used). The collapse runs inside the switch-over cutover cleanup — never as a standalone edit (dropping `root-llm` before `teller-waist` is unconditional would unwire the llm unit-plane path). | build (both distributions) green + target default line |
| 18 | **The fourth plane is STREAMING, not voice.** Voice is ONE capability/dialect inside the streaming plane; streaming can carry more than voice. No `voice` as a plane/kind/crate/feature name: the streaming plane's crate is `busbar-plane-streaming`, feature `plane-streaming`; ALL logic (dialects incl. voice, codecs, modes) lives in that one plane crate — no `busbar-streaming-codec` crate (#6/#39). The rename is byte-identical (naming/packaging, not behavior). | grep: no `voice` as a plane/kind/crate/feature name; the streaming plane is `streaming` |
| 19 | **busbar-core and busbar-voice are DELETED in 1.6.0 — the deletion is the release.** #1 requires core to name zero planes; #12 makes the internal re-architecture the release. busbar-core dissolves per #36/#37 into `busbar-kernel` (loop) + the 8 `busbar-kernel-<name>` workflow crates + `busbar-core-{admin,oauth2,connector}` (THE DESIGN §8); the fat plane crates collapse to ONE `busbar-plane-<x>` each (codecs/dialects fold IN, #39); busbar-voice is deleted (voice = a streaming dialect, #18). Byte-identical LOC move, oracle-proven; a 15-crate busbar repo with every plugin in its own repo (THE DESIGN §9). Executed as a parallel wave fan-out. | kind-isolation-ship:legacy-drain = 0; 15-crate busbar repo; shadow-oracle byte-green on every money move |
| 20 | **Transport-seam #7 extraction is IN the 1.6.0 cut.** The fat plane crates are engine+I/O; the pure `busbar-plane-*` crates enforce purity gates (~~no tokio/reqwest/async~~ SUPERSEDED 2026-09-28 by owner ruling: plugins may use any third-party library; the busbar-contract-only closure and host-owned sockets/TLS stand — a plane still opens no socket of its own (no `std::net`, no transport-kind vocabulary), no kernel-crate names, no money words, #40). The per-plane collapse is proven byte-identical: (a) ALL plane logic incl. codecs/dialects → the ONE `busbar-plane-<x>` crate (#39 — no codec crate); (b) dialing and framing → the transport plugins, pools and TLS → `busbar-core-connector` (#7/#40, THE DESIGN §5 — a plane opens no socket); (c) the engine-proper (App/state/session/secret/plane-registry/cost/governance) → `busbar-kernel`. A spot oracle box (zero-idle, terminate on close) proves each money move. | plane-purity gates green on each `busbar-plane-*`; source-denylist armable; kind-isolation-ship green; shadow-oracle byte-green |
| 21 | **A plane crate is PURE and self-contained — ONE crate holds all its logic.** `busbar-plane-<x>` holds ALL of the plane's logic — dialects, codecs, modes (#6/#39) — with no I/O, no kernel/core-crate names in its dep closure (#40). There is NO separate codec crate. The crate that dies is the fat `busbar-<x>` engine: its I/O moves to the transport plugin (#7/#40) and its remaining logic into the one plane crate. | plane-purity gates green; no busbar-*-codec crate; fat busbar-<x> engine crate deleted |

| 22 | **The money-live cutover runs unattended when oracle-green.** Retargeting each plane's live PLANE_DECL/serve onto the plane-adapter + kernel-units + transport spine, the money one-book collapse, and deleting busbar-core/busbar-voice execute autonomously; any step proven shadow-oracle byte-identical vs 1.5.5 lands. A genuine byte divergence not root-caused to agent-laziness is PARKED (cell + diff + root-cause + recommendation) and the run continues elsewhere — the ledger is never blessed upward, the oracle never waived. | shadow-oracle byte-green per step; parked-divergence log; ledger-nondecreasing |
| 23 | **A streaming session writes ONE sealed line.** The streaming plane (new; no 1.5.5 golden) admits at open; its per-turn unit reports are running checkpoints, never ledger lines; the one sealed line is written at the session's end (THE DESIGN §7). | streaming conformance rig: admit at open, running checkpoints, one sealed line per session |
| 24 | **D38 `amend_rate_history` is a real 1.6.0 money-path admin verb** — additive new admin surface (no 1.5.5 golden; it does not alter existing money cells). Spec + build it. | admin verb present + tested; oracle: existing money cells unchanged |

| 25 | **No serial phases — the money book is reached through ONE seam.** A byte-identical pass-through stub lands the money-book seam (trait + DTO) immediately, so every caller (kernel, planes, cost/governance, admin) compiles and proceeds in parallel against a stable interface. The consolidated one-book is built BEHIND the seam concurrently and activated by a one-line composition flip, shadow-oracle byte-proven — an atomic moment, not a blocking phase. Required money goldens (e.g. mid-stream upstream-error) are recorded up front in parallel, never a prerequisite that stalls work. | money-book seam present + byte-identical stub oracle-green; one-book flip oracle-green; no "serialization point" survives in the plan |

| 26 | **The teller loop dispatches by capability KEY — core names ZERO concrete callers; no `if is_admin`/`if is_mcp` chain.** Today the loop hardcodes `if is_admin { admin } else { refuse }` and NO plane is on it (admin is a cleanliness crate, NOT a plane — #5). 1.6.0 replaces that branch with a registry/capability-keyed dispatch table (#1 uniform workflow + #8 broker-by-key): every caller — admin and each plane — registers a `Units` implementation keyed by capability; the loop looks it up and dispatches, naming nobody. With only admin registered it is byte-identical. Each plane is then onboarded independently against the seams below and flipped on one at a time, oracle-proven — no `if/else` chain, no serial pole. Enabling seams, each built BOTH ends and byte-safe (unused until a plane opts in): (S1) DISPATCH — the capability-keyed loop + additive `register_units(key, impl)`; (S2) MONEY-BOOK — a settling seam + byte-identical pass-through stub over the shared durability book (#25), so exit arms compose behind it; (S3) HOST-CAPS — outbound trust anchors/SPKI pin/client identity (the connector's, THE DESIGN §5), inbound agent-card JWS/pin, server-side SSE reframe, exposed as composition-root-owned seams; (S4) HOT-ABI + drop-in loader — de-stub `busbar-plugin/hot`, loader `open_plane` + `supported_abi("plane")` + manifest claim-sealing + plane cdylib SDK + bare-bones distribution (#11). | teller-steps: loop names zero concrete callers (grep) + dispatch is table-keyed; each seam's both-ends present; per-plane flip shadow-oracle byte-green |

| 27 | **No step waits on another where a seam or fixed artifact can decouple it (generalizes #25/#26).** (a) The 1.5.5 GOLDEN is a fixed reference recorded from the 1.5.5 binary UP FRONT in parallel — only the diff needs a 1.6.0 candidate, so golden-recording never waits on a green build. (b) The busbar-core DRAIN moves each engine step behind a per-step facade/re-export in busbar-core, so steps relocate to their unit crates in ANY order (no L0→L3 chain; App/state behind a composition facade is not "last"). (c) The two arch audits run continuously against the rolling frozen SHA (they score the LOCKED architecture, fixed once the #26 seams are set), converging as code lands. (d) Plane onboarding + boot-chain assembly are additive registrations into the #26 table — parallel, never a single builder. (e) Integration stays near-parallel via disjoint per-crate agent ownership. (f) The fleet scales to prove N candidates concurrently. | the plan carries no "must finish before" that a landed seam/facade removes |

| 28 | **The loop's answer shape is two-variant `PlaneAnswer`; live streams settle per sub-unit, not by final byte count.** NAME: the two-variant type is `PlaneAnswer`, NOT `PlaneDispatch` — the shipped `PlaneDispatch` trait (`crates/busbar/src/root/transports.rs:483`, RouteLeg carrier, `DrivenOnce`; `LlmNode` builds on it) KEEPS its name and role. They COEXIST: `PlaneDispatch` carries bytes through Route; `PlaneAnswer` is what the loop settles / hands to the outer async handler. A caller's serving body produces either `Unary(status, headers, body)` — buffered, crosses the sync channel and settles at Encode on the final byte count (the admin cleanliness caller + all unary verbs, incl. SSE materialized after dispatch) — or `Live(Response)` — a live body the outer async handler serves directly, governed at admit (auth/verify/approve/admit/audit ran unary), bypassing the Encode-emits-bytes path. llm keeps its RouteLeg and emits `Live`; admin + unary verbs emit `Unary`. Live-stream settlement is the plane's, through the money-book seam at its natural sub-unit boundary: a streaming session admits at open and writes one sealed line at its end (#23); a non-billed notification channel (e.g. an mcp subscription listen stream — new plane, no 1.5.5 billing) is admission-governed and zero-metered. A plane-neutral `PlaneInFlight` binding table on ProductionUnits keyed by `ctx.key` carries per-request state (bytes/frame/principal/creds at ingress; answer at Route), mirroring `AdminUnitTable`. GOVERNANCE MODE: planes are ALREADY loop-served plane-faithfully — MCP/A2A/voice/llm-native ride a SECOND teller loop (`crates/busbar-substrate/src/teller/`) via `run_gauntlet[_session]`→`GauntletAdapter`→substrate `run_unit`, which already carries a real arena (`DispatchScope`, `crates/busbar-kernel/src/plane_host/scope.rs` — `busbar-substrate` was renamed `busbar-kernel`) through verify/approve/admit. The keystone is therefore NOT a per-plane admin-bytes bridge and NOT "first plane on the loop" — it is LOOP UNIFICATION: lift the `DispatchScope` arena onto kernel `busbar-kernel::teller::run_unit`, re-point the gauntlet riders (`busbar-llm/src/native_ingress.rs`, `busbar-a2a/.../receive.rs`, `busbar-mcp/.../method.rs`, voice `topology`, `duplex_ws.rs`) at the one kernel loop, collapse the substrate loop's TWO audit doors (`crates/busbar-kernel/src/teller.rs` `audit_refused` + admitted/abandoned) to the kernel loop's single audit step, then DELETE `crates/busbar-substrate/src/teller/` (~973 prod LOC). Prove MCP end-to-end byte-identical on the unified loop first (existing plane-faithful governance UNCHANGED — no rewrite, no asymmetry), then the rest ride the same seam. This is the single wave that clears §11a→9 AND makes §11b's per-token/POD perf+alloc benches measurable in production. LOOP-UNIFICATION IMPLEMENTATION RULINGS (three seams): (1) **THIN VERBATIM RIDER is the onboard** — the gauntlet riders re-point at the kernel loop VERBATIM, with NO `bind_book`, the kernel exit settles NOTHING, and metering stays in `drive`; full-governance-on-exit is a §11b refinement, not part of the unification. (2) **FLIP SEAM = composition-tier host selection** — a plane calls `ctx.host.run_gauntlet` UNCHANGED; the composition root installs a kernel-loop-backed host, per-plane-keyed and oracle-gated, so a plane flips onto the unified loop by composition, never by editing the plane. ~~(3) **SESSION SEAM = Option C-on-A** — the kernel governs-to-admit then hands back to the plane, returning `PlaneAnswer::Live` (empty / `ZeroHold`, no exit-settle, no `bind_book`); the plane keeps its plane-side reserve + per-turn/per-frame settle. Option B (kernel owns session settlement) is REJECTED.~~ SUPERSEDED 2026-09-28 by THE DESIGN §7 (owner): the kernel owns session money — admit at open, per-turn checkpoints in a kernel session account, one sealed line at the end; a plugin holds no reservation across the ABI. `PlaneAnswer` is the answer shape at the unified boundary. | teller-steps: plane onboarded via the loop (admin template); live verbs byte-identical on the conformance rig; loop names no concrete caller |

| 29 | **During the drain, the money oracle runs via `bin/oracle` DIRECTLY (on Latchkey, #56; the EC2 fleet is retired) — NOT through `prove-remote.sh`.** `prove-remote.sh` gates the shadow oracle behind `xtask gate --all`, which exits 1 if ANY gate is RED; the 5 core-deletion completeness gates (construction, kind-isolation, ship-ready, structure-lint, audit-ledger) are expected-RED until busbar-core deletion lands, so that wrapper is CIRCULAR (money cutovers need the oracle → the wrapper needs the gates green → the gates need the cutovers). The money byte-proof therefore runs `bin/oracle record`+`replay` directly on Latchkey, scoped to the money families, vs the 1.5.5 golden. This is NOT waiving the oracle — it still runs and must be byte-green; only the circular gate wrapper is bypassed. The 5 core-deletion gates do NOT gate the money oracle. PROVEN: the kernel-loop llm path is money-parity byte-faithful to legacy (switch-over golden 25/25 — loop==legacy on every fixture), so per-plane money cutovers are dual-write-then-flip-authority, not from-scratch byte reproduction. | money proofs use bin/oracle direct; loop==legacy switch-over golden green |
| 30 | **Every plugin kind speaks the memory ABI — seven ABIs, one per kind, on one shared mechanism. OWNER-LOCKED 2026-09-27 (THE DESIGN §11).** Owner: *"Plugins speak Memory ABI ONLY."* and *"BINGO LOCKED"*. The shared mechanism: one table of function pointers over data in fixed C layout; every call returns Ready or not-ready-with-a-wake; plugin-owned returned memory is valid until the plugin's next refresh generation; no allocation and no blocking on the hot path; slow I/O returns not-ready and fires the wake on completion, never on a blocking thread; setup and refresh via `open`/`refresh`/`tick`; the `extensions` blob on every operation; the #85 envelope on every reply; one entry point per plugin, one loading path, one dispatcher. Per kind: its own operations, data shapes and version (its v1.5.5 value + 1; new in 1.6.0 = 1); a kind evolves without forcing another kind's plugins to rebuild. JSON is only a payload — a pointer + length blob inside a field, decided once per kind; the kernel builds no JSON per request and passes the request body zero-copy (§11.3). Plane→host calls per chunk = 0 (the running unit report rides the `on_piece` return). ~~**Each plugin kind is bound to exactly ONE ABI lane, chosen by HEAT — a plugin uses the tier matched to its heat, NOT both.** There are two lanes on one seam (LOCKED §2/§3): the HOT/POD-memory lane (`#[repr(C)]` by pointer, zero-alloc, zero per-token host crossings, <1µs — LOCKED §8) and the COLD/JSON lane (serialize-per-call, off the per-token path). **The discriminator is the per-TOKEN streaming inner loop:** a kind that runs inside it is HOT; everything else is COLD. **HOT/POD lane = plane, transport** — the only kinds in the per-token loop; both are NEW in 1.6.0 (neither existed in 1.5.5), so there is no 1.5.5 byte-identity constraint on them. **COLD/JSON lane = store, secret, auth, hook, export** — all five existed in 1.5.5 as cold JSON plugins *by deliberate design* (busbar hook.rs: "off the request hot path… a serialize per call never touches request latency"); each fires per-request-once or at boot/write-behind, NEVER per-token: store=write-behind, secret=config/boot resolve, auth=one admission check per request (cached), hook=per-request phases (inbound transform mutates request IR ×N gates; decide redirects lanes ×hops; outbound is a read-only notify tap once at response head — none per-token), export=write-behind sink. Keeping the five on JSON is REQUIRED for 1.5.5 byte-identity (they ARE JSON in 1.5.5; moving them to POD would rewrite them and risk the oracle). Corollary: the "every plugin has BOTH ABIs" shorthand is SUPERSEDED — the law is "both LANES exist on the seam; each kind is assigned to one." The lane binds a kind's DISPATCH, not the host services it calls, so three things are on-lane: the running unit report riding the HOT `on_piece` return (not a crossing — plane→host calls per chunk = 0), INLINE dispatch of a CPU-only COLD plugin (no need, no `blocks` mark), and INLINE auth `decorate` once per attempt (THE DESIGN §2, §5, §6).~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.1–§11.3: the COLD/JSON lane is abolished and #30's two lanes are gone. | every kind's table lives in `busbar-contract/src/abi/<kind>/`; the ABI-location gate (THE DESIGN §11.5); one conformance suite per kind, compiled-in and dropped-in through the same table (§11.4); per-crossing microbench < 1 µs; zero-alloc hot path; plane→host per chunk = 0; debug RED: a parked read on a data worker panics ~~kind-abi-lane gate: plane/transport declare hot(POD) ABI, store/secret/auth/hook/export declare cold(JSON) ABI; a kind declaring the wrong lane ⇒ RED; per-token-loop grep = {plane,transport} only; inline COLD dispatch p99 < 100 µs (if JSON alone fails it, that is an owner question on this row); `decorate` p99 < 20 µs; debug RED: a parked read on a data worker panics~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.1 and §11.9 |
| 31 | **Plugin topology = ONE repo per plugin, outside `busbar`. OWNER-LOCKED 2026-09-18.** A plugin is a 3rd party (#2), so it lives in its own GitHub repo — never inside the `busbar` (core) repo, and never bundled into a shared plugins-monorepo (a monorepo invites cross-plugin coupling / shared test utils, which #2 forbids). This is the true 3rd-party model and matches the existing 10 clean external repos (store-{mysql,postgres,sqlite,valkey}, auth-{github,ldap,oidc}, hashicorp-vault, headroom-hook, webrequest-hook). New plugins (incl. the 4 promoted export sinks — export-{prometheus,webhook,file,otlp}, #3) are created as NEW repos templated from those 10. The DEFAULT distribution still compiles a plugin in by depending on its repo (compiled-in vs dropped-in = packaging only, #11) — the plugin SOURCE never re-enters `busbar`. **The multi-repo drift risk (the 10 had drifted to 4 different pre-1.5.5 core pins — 1.5.0/1.5.2/1.5.3/1.5.4 — because each `.busbar-ref` was bumped independently) is solved by TOOLING, not topology:** a release-train step bumps every plugin repo's `.busbar-ref` to the released core SHA in one lockstep pass (the reusable `plugin-ci.yml` already materializes core as a sibling), and this tooling is EXPANDED to cover every new plugin repo as it is created. Independent repos + one-command lockstep pin. Fleet: repos named `busbar-<kind>-<name>`, each a logic crate plus a plugin crate with its own semver and declared contract-ABI range, promoting on its own dev/qa/main, generated and checked from `plugins.yaml` + `.github/fleet/` (THE DESIGN §9). | plugin repos live under GetBusbar/<plugin>, never crates/ in busbar; release-train pin-bump covers all plugin repos incl. new ones; no plugins-monorepo |
| 32 | **Release-train CI across all repos — OWNER-RATIFIED 2026-09-18.** BRANCH FLOW is `dev → qa → main` in EVERY repo (busbar + every plugin repo in the §9 roster + downstream tooling; plugin repos are twins working on `dev`); **never push to `main` directly** — promotion happens only through CI, driven by the busbar main build. All development lands on `dev`; nothing advances past `dev` until the busbar main build conducts it. CONDUCTOR = **turnstile** (the existing merge-queue/land + EC2-fleet orchestrator, extended to drive releases). The train, on a busbar release SHA: (A) core 21-group done-oracle green on CORE_SHA (single source of truth); (B) PIN-LOCKSTEP — one turnstile dispatch rewrites every manifest repo's `.busbar-ref` → CORE_SHA on `dev` (kills the multi-repo drift that left plugins pinned to 1.5.0/1.5.2/1.5.3/1.5.4); (C) per-plugin verify via the reusable `plugin-ci.yml` (two-leg matrix, real service containers, pack+sign gate); (D) REVERSE CONSUMER-VERIFY — busbar's DEFAULT distribution build git-deps each `compiled_in_default` plugin at its bumped SHA and runs the oracle byte-identical (a BUILD-only concern — plugin SOURCE never re-enters busbar); (E) all green → turnstile promotes each repo dev→qa→main, tags, publishes signed cdylibs + busbar binary, fires downstream bumps (homebrew/helm/tf-provider). ROSTER = `plugins.yaml`, the first-party plugin registry; adding a plugin = one entry, and the registry gate, the fleet check and the train cover it (THE DESIGN §9). | branch protection: no direct main push in any repo; turnstile conducts dev→qa→main; manifest-driven pin-lockstep + consumer-verify + drift-check green before any promotion |
| 33 | **Plugin infrastructure = ONE crate atop the ONE contract crate (#38). OWNER-LOCKED 2026-09-18.** The author side — the door macro `export_plugin!`, per-kind dispatch and the boundary glue — lives in `busbar-contract` (#84 merged `busbar-plugin-sdk` into it), so a plugin's busbar closure is exactly `busbar-contract`. `busbar-plugin-loader` = **how core loads plugins** (host side): open/verify/identify/call + signature verify (former `busbar-plugin-sign`) + tarball pack (former `busbar-plugin-pack`). There is **NO `testkit`** (dead — not a crate and not a feature): each plugin **self-tests** (#2); the kernel tests no plugin. **A KIND is a match-arm, not a crate; an INSTANCE is a repo** (#31). | plugin-infra crate count = 1 (`busbar-plugin-loader`) over `busbar-contract`; no busbar-plugin / -sdk / -sign / -pack / -testkit crate; no `testkit` feature anywhere; the door macro lives in busbar-contract; sign+pack in loader; kinds are match-arms; instances are repos |
| 34 | **Universal crate naming = `busbar-<major>-<…>`, where a KIND is its own major. OWNER-RATIFIED 2026-09-18 (scheme A).** `major` ∈ { `plugin` (the plugin ABI MACHINERY only — now just `busbar-plugin-loader`, #33), `core` (the engine), OR a plugin KIND: `store`/`secret`/`auth`/`hook`/`export`/`plane`/`transport` }. A store plugin is `busbar-store-postgres` (store stuff — the word `plugin` is RESERVED for the contract machinery, never prefixed onto instances). `plane`/`transport` already follow this (`busbar-plane-mcp`, `busbar-transport-http`); the outliers to align are the external store/secret/auth/hook repos (`store-postgres`→`busbar-store-postgres`, `hashicorp-vault`→`busbar-secret-vault`, `auth-oidc`→`busbar-auth-oidc`, `{headroom,webrequest}-hook`→`busbar-hook-{…}`) plus `busbar-hooks-ranking`→`busbar-hook-ranking`. Kernel/core tier per #36/#37: the 14 `busbar-unit-*` retire into the 8 `busbar-kernel-<name>` (#36); `busbar-{admin,oauth2}`→`busbar-core-{admin,oauth2}`, plus `busbar-core-connector` (#37); `busbar-kernel` KEEPS its name (its own tier, #37); `caps`/`grammar`/`timing` are KILLED/folded (#37), not renamed; `busbar-contract-transport` FOLDS INTO `busbar-contract` (#38, no rename). `busbar` (the binary) stays. Codecs fold into the plane crate — NO `busbar-*-codec` crate (#39). **TIMING:** scheme locked now; in-tree `git mv`+Cargo-repoint runs as ONE atomic wave once the open codeaudit-fix branches fold (renaming 60 crates against live branches = conflict hell); the external GitHub repo renames (+redirects, homebrew/helm/tf) run now, with the fleet (THE DESIGN §9). **ALL plugin instances = `busbar-<kind>-<name>`** (owner-confirmed 2026-09-18): `busbar-store-postgres`, `busbar-transport-http`, `busbar-secret-vault`, `busbar-auth-oidc`, `busbar-hook-headroom`, `busbar-export-prometheus`, `busbar-plane-mcp`. **RESOLVED (was OPEN):** the `busbar-api`/`busbar-contract` smell is settled by #35 — not a rename but a fold (sealed ABI→`busbar-contract` #38, kernel+money records→core); `busbar-api` retires. | crate names conform to busbar-<major>-<…>; all plugin instances are busbar-<kind>-<name>; `plugin` only on ABI machinery; kinds are majors; a naming gate greps for non-conforming crate names |
| 35 | **`busbar-api` + `busbar-contract` are NOT a layered pair — they fold into the 2 infra crates + core. OWNER-LOCKED 2026-09-18; analysis a6a9bda.** The two crates are independent siblings (neither deps the other) that COLLIDE on five false-friend names — `Store`, `StoreError`, `SecretError`, `SecretRef`, `AuthOutcome` — each a *different* type sharing an identifier (e.g. contract::Store = 22-method `Plugin`-bound journal ABI; api::Store = 31-method domain-record CRUD bound to nothing). Not duplication, not layering: two generations of "the plugin contract crate." DISPOSITION: (a) the **sealed plugin-visible ABI** — the closed `Kind` taxonomy + `KindMarker`/`Plugin` base + one capability trait per kind + bounded/grammar vocab — is the neutral ABI both sides name, so it lands in **`busbar-contract`** (#38 — the ONE ABI crate, NOT the sdk); (b) the **kernel vocab + money-path durable records** — `Scratch`(the renamed arena, #41)/`Unit`/`Ctx`/`Facts`/`Ir`/`RoutePlan` and the serde wire records `VirtualKey`(HAND-written wire)/`UsageLedger`/`MeteringRow`/`AuditRecord`/`PlaneRecord`/`CredentialSecret` — are **CORE**, not plugin infra, and move under the core-naming pass (next agenda). **BYTE-IDENTITY GUARD:** the money-path records relocate module-path-ONLY — serde field names / wire bytes must not change; `VirtualKey`'s hand-written `virtual_key_wire` module travels verbatim; the oracle proves it. The five colliding api-side names de-collide on the move (`RecordStore`/`RecordStoreError`/`SecretModuleError`/`SecretConfigRef`/`AuthVerdict` or equivalents chosen at implementation). `busbar-api` as a distinct crate is RETIRED. | no busbar-api crate post-fold; sealed-ABI types in busbar-contract (#38); kernel+money records in core (byte-identical, oracle-gated); zero false-friend name collisions remain |
| 36 | **Kernel workflow = 8 crates in 4 groups; the word "unit" is retired. OWNER-LOCKED 2026-09-18.** The 14 `busbar-unit-*` crates collapse to **8 `busbar-kernel-<name>`** crates (flat names, group is conceptual only). GATES (the 3 door decisions — who → may → afford): `busbar-kernel-identity` (the AUTHENTICATE step: a presented credential resolved to a principal; the outbound per-request auth call is the auth kind's, THE DESIGN §6), `busbar-kernel-scope` (authZ: declared bar, ceilings, revocation), `busbar-kernel-budget` (the afford gate: try_admit/refund, D7 check-then-charge). MONEY: `busbar-kernel-ledger` (the book — rates+usage+ledger merged, three modules; persists via wal). EGRESS: `busbar-kernel-egress` (the upstream leg — walk + swrr weighting + pre-dial guard; trust folded in), `busbar-kernel-breaker` (trip/cooldown/fast-fail per pool,dest). JOURNAL: `busbar-kernel-wal` (the write-ahead append primitive — ledger AND audit ship through it), `busbar-kernel-audit` (the one append-only chain). EXITS from the unit set: `verbs` → `busbar-core-admin` (admin owns its own execution — no codec/exec split, since admin is a cleanliness crate not a plane); TLS provisioning → **`busbar-core-connector`**, the only holder of TLS keys, certificates, trust roots and mTLS identity; there is no tls plugin (THE DESIGN §5, §8). `busbar-kernel` itself = the loop/registry/teller/sessions. | no busbar-unit-* crates; 8 busbar-kernel-<name> crates; naming gate greps the set |
| 37 | **Core dissolves to 3 cleanliness crates; no plugin-kind name in the core tier. OWNER-LOCKED 2026-09-18.** `busbar-core` is deleted (#19); the surviving compiled-in scaffolding = exactly **`busbar-core-admin`** (admin codec + verb execution), **`busbar-core-oauth2`** (OAuth AS + hosted login flow) and **`busbar-core-connector`** (composition + TLS) — THE DESIGN §8. `busbar-core-substrate` held two definitions and SPLIT (#83a): the pure leaves → `busbar-contract`, the machinery → `busbar-kernel`; `busbar-core-connsec` folds into the connector. The fat `busbar-substrate` (30k runtime shell) is DELETED — its runtime half drains to the kernel-8/units, `plane_host/` deleted, pure-value leaves (civil/duration/clock/config-enums/audit-vocab) → `busbar-contract`. RULE (a kind is a plugin, never a core crate): **no `busbar-core-<kind>` ever** — kills `busbar-core-hooks` (hook is a kind → `busbar-hook-*`). TIER meaning: `busbar-kernel*` = the engine+workflow (the loop); `busbar-core-*` = compiled-in scaffolding around it, one-way dep on the kernel. Killed/folded: `busbar-core-{hooks,config,caps,grammar,timing}`, `busbar-substrate-values`(name) → contract/kernel/binary. | only busbar-core-{admin,oauth2,connector} carry busbar-core-*; no core-<kind> crate |
| 38 | **`busbar-contract` is the ONE contract/ABI crate; `contract` is a reserved major. OWNER-LOCKED 2026-09-18 (amends #33/#35).** ALL seven kinds' capability traits + Kind taxonomy + every kind's ABI shapes, and only under `src/abi/` — `mechanism/`, one folder per kind, `host/`, `sdk/`, plus a generated C header (THE DESIGN §11.5) ~~+ BOTH lanes' wire types (COLD/JSON and HOT/`repr(C)`, #30)~~ (SUPERSEDED 2026-09-27 by THE DESIGN §11.1) + the neutral vocab (ids, grammar, caps, values, wire, civil/duration, audit vocab) live in **one crate: `busbar-contract`**. NO per-kind contract crate — `busbar-contract-transport` FOLDS IN (a KIND is a match-arm, not a crate, #33; contract already depended on it and already had a `transport.rs`). It is the neutral ABI both sides name, so it is **un-prefixed on purpose** — `contract` is its own reserved major in scheme A alongside `plugin`/`core`/`kind` (prefixing it `plugin-`/`core-` would lie about ownership). The author-side SDK (the door macro, dispatch glue, the typed wrappers) lives IN `busbar-contract`, at `src/abi/sdk/` (#84; THE DESIGN §11.5); plugin machinery = `busbar-plugin-loader` (host-side open/verify/call + sign + pack) atop the one contract; NO testkit (#33). `busbar-api` retires; its record SHAPES → `busbar-contract`, their semantics → `busbar-kernel-ledger` (#83; byte-identical, oracle-gated). **Three properties of the contract surface:** (a) **no default bodies** — every method of every kind trait is implemented by the plugin, because *"a default body is a plugin quietly declining to answer"*; (b) **feature-invariant** — no feature changes the surface a plugin compiles against (the only features are the named exemptions in `feature_invariance.rs`, incl. the dev-only `test-seal`); (c) **bounded** — every collection has a ceiling that is part of its type, except the candidate set and its permutation, which stay unbounded because bounding them would refuse a configuration 1.5.5 accepted. A hold has no `Drop` of its own: *"a hold that goes away without a posting is a bug the canary must see, not a thing a destructor should paper over."* | exactly one *-contract crate (busbar-contract); no busbar-*-contract; no busbar-plugin-sdk crate; the loader depends on contract; the ABI-location gate: no C-layout struct, ABI fn-pointer type or ABI version constant defined outside `busbar-contract/src/abi/` (THE DESIGN §11.5) |
| 39 | **Every plugin = 1 repo, all 7 kinds; the busbar repo holds NO plugin source and exactly 15 crates. OWNER-LOCKED 2026-09-18; plugins in their own repos OWNER 2026-09-25.** Plane and transport are plugin kinds, so each instance is its own repo exactly like store/secret/auth/hook/export (#31). Codecs, dialects and modes FOLD INTO the plane crate — **planes = exactly 5**, `busbar-plane-{llm,mcp,a2a,streaming,decisions}` (#48; no `busbar-*-codec`, no `busbar-plane-mcp-host`). The busbar repo and every plugin repo are listed in THE DESIGN §9: the busbar repo holds `busbar`, `busbar-kernel` + the 8, `busbar-contract`, `busbar-plugin-loader` and `busbar-core-{admin,oauth2,connector}`. The default distribution compiles a subset in by depending on the plugin repos at pinned versions (#11) — plugin SOURCE never re-enters busbar. There is no in-tree plugin and no fixture plugin: real plugins are the both-ways proofs (#2). | busbar repo crate count = 15; zero plugin crates in busbar; 1 plugin = 1 repo for all 7 kinds; planes = 5 repos (incl. decisions) |
| 40 | **Plugin capability isolation — plugins talk to busbar ONLY over the ABI, enforced physically on the plugin→busbar channel. OWNER-LOCKED 2026-09-18.** Treat every plugin as untrusted 3rd party. THREE walls: (a) **dep-wall** — a plugin crate's entire workspace dependency closure = `busbar-contract` and nothing else; a RED-provable `kind-isolation` CI gate runs `cargo metadata` on every `busbar-<kind>-*` crate and asserts closure ∩ {kernel, core-*, any secret impl, any other plugin} = ∅ (you cannot `use` what you cannot name); and no socket2 or `tokio/net` anywhere in the closure, ~~and no ... reqwest, hyper client, rustls or redis `aio` anywhere in the closure,~~ SUPERSEDED 2026-09-28 by owner ruling: plugins may use any third-party library; the busbar-contract-only closure and host-owned sockets/TLS stand — proven by a post-LTO import scan — the carrier plugins are the one named exception (THE DESIGN §5). (b) **capability-ABI** — every privileged resource (`ConnId`, need, auth object) crosses ONLY as an opaque kernel-minted `#[repr(C)]` handle with ZERO byte-accessor on the plugin surface; secret bytes reach a plugin only on the two audited paths under SECRETS. (c) **FFI vtable** — a dropped-in cdylib calls back into busbar ONLY through the host-callback function pointers the kernel handed it at init (= the ABI); no kernel-internal symbol is in its link table, so `kernel.somethingMalicious()` is unrepresentable. SECRETS: the SECRET kind returns material to the KERNEL; the kernel resolves+audits; it delivers secret material only to (a) the auth object bound to it and (b) the non-plane plugin whose settings reference it, as in 1.5.5; a plane never receives secret bytes; framers see decorated headers in transit; TLS keys never leave `busbar-core-connector`; every plugin that holds a credential is operator-trusted (THE DESIGN §6). HONEST CEILING: (a)+(b)+(c) physically wall channel-1 (plugin→busbar) for native, plus mandatory code-signing at load (loader refuses unsigned). Channel-2 (plugin→OS: fs/net/host-RAM) is walled only by a runtime sandbox. **1.6.0 model = posture A** (native + code-signing + capability-ABI + dep-wall). **Posture B** (WASM confinement of the five kinds once called COLD — esp. `secret` — to wall channel-2) is OWNER-TABLED, not in the 1.6.0 crate/security model. | kind-isolation dep-gate green (RED-provable); no secret-bytes accessor on the ABI surface; RED: a plane echoing its whole request and response never sees a credential; loader refuses unsigned; posture A |

| 41 | **Scratch memory GROWS on demand — never a fixed cap, never a crash. OWNER-LOCKED 2026-09-20 (kills the "arena" model + its fixed-4KiB-refuse design).** Per-request scratch: trait `Scratch` (in `busbar-contract`), impl **`ScratchPad`**, module `busbar-kernel::scratch` — the name "arena" is DEAD everywhere (`ArenaBytes`→`Scratch*`). Backed by an audited chunk-chaining bump allocator (bumpalo); `busbar-kernel` stays `forbid(unsafe)`, dep NOT added to `busbar-contract`. **It GROWS ON DEMAND by adding chunks — it never crashes and never issues a size-based refusal (`ArenaExhausted`/`ArenaBudget` for size is GONE).** The old fixed-4 KiB-cap-that-refuses (`set_allocation_limit`, per-worker fixed pool, backpressure-past-N) is KILLED. 4 KiB is only a STARTING size (a perf hint, MEASURED by the architect across planes and reported, not guessed); a big request pays one heap grow instead of crashing. **Shrinks back** to the starting size after a big request (no worker permanently hoards). **Abuse-only backstop**: a ceiling set absurdly high that only a runaway/attack could hit; on trip it cleanly refuses THAT ONE request, never panics. Kernel-owned; planes are size-blind. Proof case: jev (~5 KB responses) throws `ArenaExhausted` on the fixed 4 KiB today — the live bug this fixes. Runtime unchanged (`!Send`, thread-per-core LocalSet). | scratch grows (no set_allocation_limit ceiling); zero `ArenaExhausted`/size-refuse on the serve path; jev ~5KB serves; grow-then-shrink test; abuse-backstop test refuses-one-not-panics; grep: no "arena"/"Arena" type names |
| 42 | **THE MONEY MODEL — one model, locked across six rows; read them together: #42 (this — the billing switch), #43 (plugins pricing-blind, pricing is a read-time view), #44 (flat fee = one dimension, never rounded), #66 (unitless — no currency/symbol), #71 (ledger = raw counts, hot path carries no money math), #77 (the 10 core invariants). These are FACETS, not duplicates — each is cited by number (incl. granular #77(1)/#77.8) across the gates, CI, and kernel/ledger code, so the numbers are load-bearing anchors and stay. — Billing is OPTIONAL per plane; rate_card PRESENCE is the switch; there is NO `billing:on/off` flag. OWNER-LOCKED 2026-09-20.** rate_card PRESENT ⇒ billed: a hit class not priced ⇒ **REFUSE** (money-sacred, never a silent 0). rate_card ABSENT ⇒ NOT billed: a cost request reads **0**, serve free, no metering, no ledger charge, no afford-gate, no boot-refusal — busbar runs as a pure failover/routing proxy (the "user X wants failover on breaker-trip, doesn't care about billing" case). **A cost request returns: the price if billing-on & priced; FAILS if billing-on & unpriced; 0 if billing-off. A silent 0 is ONLY ever returned when rate_card is absent.** This EQUALS 1.5.5 (`config.yaml:394` "absent = tokens price 0; present = EVERY configured model needs an entry") — no divergence, now scoped per plane. `cheapest` with billing off: all candidates read 0 → tie → cost hook is a no-op → route by failover/health/weight. An unbilled plane STILL gets admission/concurrency + breaker enforcement (proxy, not unlimited); audit still records the request (no spend). | billing-off plane: cost=0, serves, zero meter/ledger rows, no boot-refusal, breaker+concurrency still enforced; billing-on + unpriced class ⇒ refuse; silent-0 appears only when rate_card absent |
| 43 | **rate_card + fees are CORE-owned; plugins are PRICING-BLIND; pricing is a read-time VIEW. OWNER-LOCKED 2026-09-20.** A plane plugin NEVER sees its rate card or fees. Pricing is CORE functionality, not a plane/plugin concern. A plane emits USAGE FACTS only (e.g. `output_utok: 17`); the ledger records the fact once; **pricing is a read-time VIEW** core lays over recorded facts using the rate card (read-time conversion never stored — money model). `rate_card` + `fees` are RESERVED, core-owned config sub-keys: authored in config alongside a plane's own settings for ergonomics, but core **STRIPS them from the blob before it crosses the plugin ABI** (mirrors the `pools:` reserved-section-keys pattern, `config.yaml:187`; extends #40 — as secrets never cross the ABI, money never crosses it). **ENFORCEMENT + MEASURED VIOLATION (2026-09-22, owner restated this as \"planes always ledger\" / \"it's a kernel default all planes run through\"):** a plane appends its counts UNCONDITIONALLY — no branch, no knowledge of billing state. `rate_card` is optional per plane IN CONFIG (#47); the switch is a READ-TIME property of the money VIEW, kernel-side, so \"billing off\" means the VIEW reads 0 (#42), never that the plane skipped the ledger. #42's \"optional per plane\" always described the CONFIG KEY and the VIEW, never a conditional inside plane code. **The code does not match:** plane crates carry money references where this row says they carry none — `busbar-plane-streaming` 41, `-a2a` 30, `-mcp` 29, `-llm` 16, `-decision` 9 (matching `rate_card|nanos|price|spend`) — and each `crates/busbar/src/root/units_*.rs` REIMPLEMENTS the same rulings: `units_a2a` 5 accrue/3 rate_card_version/37 nanos-hold, `units_llm` 5/1/37, `units_mcp` 2/4/26, `units_voice` 7/2/61. **The duplication is the defect generator and today proved it:** `UnitKey::new(0)` was fixed at `units_a2a.rs:1019` while the identical bug still sits at `units_mcp.rs:1481` — independently written, independently wrong. END STATE: ONE kernel-side implementation of accrual, provenance and keying; a plane emits counts per its declared class and nothing else. | RED-provable gate: zero `rate_card`/price/nanos/spend references in any `busbar-plane-*` crate; accrual+provenance+keying in exactly ONE kernel-side place; no reserved money sub-key (`rate_card`,`fees`) ever appears in the serialized blob handed to any plugin; plane plugins have no pricing type on their surface; ledger stores facts, price computed at read |
| 44 | **Money model is plane-agnostic: flat fee is one dimension, never rounded. OWNER-LOCKED 2026-09-20.** A flat/static fee is ONE plane-agnostic pricing dimension on the rate card (applied per-request or per-session), identical for every plane, and **NEVER rounded**. Per-unit rates use each plan's own declared units (tokens/seconds/frames/…); only a "per-N-units" division term uses banker's (half-to-even) rounding; card-build-time quantization stays half-away-from-zero (byte-identity). The LLM per-request fee stays a straight multiply (no division, no rounding) — it is NOT re-expressed as a per-unit term. Rate-card version is **VISIBLE** on usage/audit reports (pricing provenance), not internal-only — served on the usage and audit responses as an `additive` register entry (owner, 2026-09-27). | flat fee never divides/rounds for any plane; only per-N-units terms round (banker's); card-build quantization unchanged (oracle byte-identity); rate_card_version surfaced on usage+audit endpoints |
| 45 | **Streaming/voice: a session holds a capacity slot for its whole life; first billable cut = OpenAI+Gemini+Twilio; media stack is adopted. OWNER-LOCKED 2026-09-20.** A live session HOLDS a capacity slot for its whole life — one admission end-to-end (one accept, one billing key, one cleanup), guaranteed capacity to continue (1.5.5 parity N/A — it had no streaming). First billable voice cut = **OpenAI Realtime + Gemini Live + Twilio telephony**; browser WebRTC (Pipecat/LiveKit class) follows in the same release. Media stack for the browser/phone audio leg = **ADOPT an existing open-source realtime-media framework**, NOT a hand-built native pump (server-to-server bridges don't need it). **Voice scope (owner, on or before 2026-09-04):** OpenAI Realtime over WS and WebRTC, with busbar terminating WebRTC; Gemini Live as a second egress dialect; one-shot transcribe/TTS as HTTP units; Twilio Media Streams as a WS-carried transport with a μ-law codec; raw SIP is not carried. **Tools mid-call** are relayed to the client AND executable through the MCP plane as a governed cross-plane destination. **Scope as ruled 2026-09-29 (OWNER):** exactly three dialects — OpenAI Realtime (WS and WebRTC), Gemini Live and Twilio; SIP is not carried; streaming work follows the mcp, a2a, llm and decisions work (THE DESIGN §2, §5). **Browser trust boundary** — a security invariant, tested adversarially: the browser gets only a short-lived ephemeral secret, never holds the real key, never authors tools or instructions, and cannot override the session's locked instructions. | session = one admission/one billing key/one cleanup, slot held for life; first-cut dialects = openai-realtime+gemini-live+twilio; media leg uses an adopted framework, not an in-house pump; adversarial browser-client RED arms (real key never served, client-authored tools and instruction overrides refused) |
| 46 | **The `cheapest` hook is plane-agnostic; expected-units profile is plane-declared with an operator override. OWNER-LOCKED 2026-09-20.** `cheapest` ranks on estimated total cost = Σ over billing classes of `price-per-unit × weight`, the weights being the plane's declared `route_cost` and the prices the card in force by opaque lane key (THE DESIGN §2, §7); the strategy words are aliases the ranking plugin declares; it names ZERO plane/llm concepts (neutrality witness / protocol-noun grep-ban covers it). For quantities a request can't reveal up front (voice seconds, relay frames), the plane declares a default `expected_units` per metered class (neutral, travels with the class); an operator MAY override per-pool/per-hook in hook settings to tune ranking without a plugin rebuild. Precedence: operator override wins if present, else plane default; empty/unknown price ⇒ sorted LAST, never 0. | cheapest carries no plane/llm noun (grep); expected_units default is plane-declared; operator override honored; unknown price sorts last (never 0) |

| 47 | **1.6.0 config = one section per plane; `models` stays a root key beside `pools`; rate_card+fees are per-plane reserved keys. OWNER-LOCKED 2026-09-20.** Each plane gets its OWN top-level config section: **`pools`** (llm), **`tools`** (mcp), **`agents`** (a2a), **`decisions`** (jev, #48), **`streams`** (streaming). `models:` stays its own root key beside `pools`, the 1.5.5 shape; the llm plane owns both (THE DESIGN §4). `rate_card` + `fees` are RESERVED core-owned sub-keys inside each plane's section (#43): core strips them before the blob crosses the plugin ABI — as it does every reserved sub-key (`breaker`, `on_exhausted`, `gates`, `upstream_credentials`, `affinity`, `tier`, `repeatable`); tool and agent pools sit under their plane's verb as a reserved `pools` sub-key; `store:` is required (THE DESIGN §4). rate_card entry shape is the existing `RateEntryCfg` (`input_utok`/`output_utok`/`cache_read_utok`/`cache_write_utok`, `busbar-substrate/src/config/sections.rs:324`); `fees` = `{ per_request | per_session }` (#44). Top-level infra keys unchanged from 1.5.5 (`listen`, `admin_listen`, `identity-providers`, `auth`, `providers`, `groups`, `store`, `export`, `plugins`, `security`, `advanced`). Back-compat: 1.5.5's flat top-level `rate_card`/`per_request_fee` load as the `pools` (llm) plane's reserved keys, byte-identical. | config has a section per plane (pools/tools/agents/decisions/streams); `pools` and `models` are both root keys of the llm plane; rate_card/fees per-plane and stripped at the ABI (#43 gate); 1.5.5 flat rate_card still loads as llm |
| 48 | **jev is the `decisions` plane — planes = 5, not 4. OWNER-LOCKED 2026-09-20 (amends #18/#39).** jev (typesafe.ai decision API; ~5 KB unbounded responses — the Scratch proof case, #41) is a busbar PLANE, configured under the `decisions:` section (#47). OWNER RULED 2026-09-27 (*"decisions feels right"*): plane id `decisions`, crate and repo `busbar-plane-decisions`, feature `plane-decisions`; its `KEY` and meter class stay `"decision"`. The locked plane roster becomes **5**: llm, mcp, a2a, streaming, **decisions(jev)** — amending #18/#39's count of 4. Plane rules are otherwise unchanged (1 plugin = 1 repo = 1 crate, #39; ~~HOT/POD lane, #30~~ the memory ABI, THE DESIGN §11). OWNER RULED 2026-09-29/30: the decisions plane is N dialects over an IR, like llm; the engines named so far are providers of its one dialect (protocol `jev`), and NanoJev is the second dialect (THE DESIGN §2). | plane roster = 5 incl. decisions(jev); `decisions:` config section exists; jev crate is its own repo like the other planes |

| 49 | **The kernel knows NO plane or transport STRINGS — everything is data from config + each plane's declared config verb. OWNER-LOCKED 2026-09-20.** Core/kernel contains zero plane-instance literals ("llm"/"mcp"/"a2a"/"streaming"/"decisions") and zero transport-protocol/scheme literals ("http"/"https"/"ftp"/"anthropic"/"openai"/…). The config SECTION name for a plane comes from that plane's Statement `sections.owns` (pools/tools/agents/streams/decisions, #47; THE DESIGN §2) — the plane owns its verb, core hardcodes none. The transport wire (`protocol`, `base_url`, `error_map`) is DATA read from the `providers.yaml` catalog (`providers_file:`, `config/mod.rs:1146`) merged with config `providers:` creds at startup (`mod.rs:2016/2077`); the connector dials whatever resolves, inventing no scheme (THE DESIGN §5). `providers` = the transport-config verb (global, all planes); the per-plane target invoked over it is `models` (pools/streams/decisions) / `servers` (tools) / `agents` (agents), uniform schema `{ provider, protocol?/dialect? (override, #51), upstream_model?, error_map? (override, #51), …caps }` (no `id:` key — map key IS the id). This is the neutrality witness in force: a plane/transport is added by config + a plane crate's const, never by editing core. | grep gate: kernel/core crates contain no plane-instance or transport-scheme string literal; plane config verbs come only from Statement `sections.owns`; transport protocol/base_url resolved from providers.yaml+config, never hardcoded |

| 50 | **Transport is selected by the provider's base_url SCHEME; each transport plugin DECLARES the scheme(s) it serves. OWNER-LOCKED 2026-09-20 (reconciles #49; resolves the "providers vs transport verb" conflict).** `providers:` remains the transport CONNECTION-config verb (#49) — base_url + credential ref per upstream. Each TRANSPORT plugin declares the URL scheme SET it handles: e.g. `busbar-transport-http` serves `http`+`https`; a websocket transport serves `ws`+`wss`; a stdio transport serves `stdio`; etc. (that declared scheme-set is what the owner calls the transport's "own config verb"). At BOOT the kernel matches every provider's base_url **scheme** against the registered transport plugins' declared scheme-sets and the connector activates the matching plugin; **no match ⇒ fail closed**, naming the provider + the unserved scheme. The http framer claims `http` AND `https`; `https` inserts the connector's TLS. The auth style resolves the same way — the entry's `auth:`, else the plane's dialect default — as opaque strings (THE DESIGN §5, §6). The kernel names no scheme string (#49) — the mapping is data: provider base_url (config) × plugin-declared schemes (plugin). Adding a new wire = drop in a `busbar-transport-<x>` declaring its scheme(s), reboot, zero kernel edits. So `providers` (connection) and per-transport scheme declaration are COMPLEMENTARY, not competing: there is no separate top-level config section per transport. | boot matches base_url scheme → the transport plugin declaring that scheme; unmatched scheme ⇒ fail-closed naming provider+scheme; kernel contains no scheme literal (#49 gate); transport plugin manifest declares its served scheme-set |

| 51 | **A provider is a CONNECTION with a DEFAULT wire protocol; the plane resolves and can OVERRIDE it, and the plane always interprets it fail-closed. OWNER-LOCKED 2026-09-20 (amends #49).** A `providers:` entry = connection (`base_url`, `api_key`, `path`/`path_base`) PLUS a **default `protocol`** (and default `error_map`) supplied by the shipped `providers.yaml` catalog. The default stays on the provider ON PURPOSE — with 100+ catalog entries, an operator must NOT have to know e.g. that `z.ai` speaks the openai wire protocol; the catalog knows it. **But the wire format is ultimately the PLANE's**: a plane's model entry may **OVERRIDE** the protocol/dialect (e.g. the same `anthropic` connection used on the streaming plane with a streaming protocol when Anthropic ships one). Resolution: model override if present, else the provider/catalog default. `error_map` follows the same rule (catalog default on the provider, per-model override). **The PLANE then interprets the resolved dialect against what it supports: knows it ⇒ use it; doesn't ⇒ FAIL (fail-closed)** — e.g. the decisions plane (only jev) handed `anthropic` fails. Dialect validation is the plane's job, never the kernel's; the kernel opens the transport from the base_url scheme (#50) and hands the plane the connection + resolved dialect. Model entry = `{ provider, protocol?/dialect? (override), upstream_model?, error_map? (override), …caps }`. Provider keeps `protocol`/`error_map` (byte-compatible with 1.5.5); the model-side override is NEW/additive — minimal migration. A protocol may be MODEL-ONLY — never a provider default (ARCHITECT ruling 2026-09-30, THE DESIGN §2). | provider = connection + default protocol/error_map (catalog-supplied); model may override protocol+error_map; resolution = model-override-else-provider-default; plane interprets resolved dialect, unknown ⇒ fail-closed; kernel validates no dialect |

| 52 | **Admin API ↔ config = full parity, enforced by a build gate. OWNER-LOCKED 2026-09-20.** Every config-file setting is ALSO settable live over the admin API; the admin API and the config file are ONE schema (two front doors: file at boot, admin at runtime). A RED-provable build gate fails if any config field lacks a matching admin route, so the two can never drift. | config↔admin parity gate: every config field has an admin route; build fails on any gap |
| 53 | **The secret-hygiene scan is a hard release blocker. OWNER-LOCKED 2026-09-20.** The scan for in-the-clear secrets (bare-`String` holds etc.) moves from report-only to BLOCKING: a bare/unwrapped secret fails the ship gate. The currently-flagged holds must be fixed (wrapped in the `Secret` type, #54) before 1.6.0 cuts. One exemption is written down rather than buried in a needle list: a credential-bearing URL bound to a `*_url`/`*_uri` name is waived by construction (`token_url`, `token_uri`), the one place the scan trades a real hole for signal (2026-09-23). | secret-hygiene gate blocks the ship gate (RED on any bare secret); flagged holds fixed before cut |
| 54 | **Secrets use a dedicated `Secret` type, not a bare string + lint. OWNER-LOCKED 2026-09-20.** A first-class `Secret<T>` (not merely a `Redacted` wrapper + gate): the TYPE itself enforces the safety — it cannot be passed into disallowed code paths (type-level flow restriction), and its `Debug`/`Display`/`.to_string()` render `REDACTED` (never the value). Raw value access is a single explicit sealed method (KernelSeal, #40). Stronger than "String + if-checks." The behaviour the type serves (owner, 2026-09-01): *"secrets can never enter logs or audits. Secret ID yes, not THE secret."* — logs, audit records and metrics carry the secret's reference (`SecretRef`, key id), never its value (THE DESIGN §6). | secret material is `Secret<T>`; Debug/Display/to_string ⇒ REDACTED; no bare-String secret survives the #53 gate; raw access only via the sealed accessor |
| 55 | **1.6.0 ships on plugin security posture A; OS-level sandbox tabled — OWNER-CONFIRMED 2026-09-20 (affirms #40).** 1.6.0 walls plugins via code-signing (loader refuses unsigned) + the dep-wall + capability-ABI/KernelSeal (#40); confining a plugin from the OS (files/network — "channel-2", WASM posture B) is not part of 1.6.0 (owner-tabled), and is not a cut blocker. Plugins remain signed + trusted-only. | ship 1.6.0 posture A; WASM/OS-sandbox not a cut gate; loader refuses unsigned |

| 56 | **CI runner priority = Latchkey-primary; money/oracle allowed on Latchkey; EC2 zero-idle burst-only. OWNER-LOCKED 2026-09-20 (reverses the shipped EC2-only + GH-first defaults).** Latchkey is the PRIMARY runner (LK > EC2) — its self-healing "red→green" risk is proven solved, so **money/oracle jobs MAY run on Latchkey** (`allow_money_on_latchkey` → true), reversing the earlier EC2-only default. **GitHub-hosted is used only for jobs known not to hit resource limits.** **EC2 sits at floor 0 when idle and bursts only** when LK (and safe GH) can't absorb load — no always-on on-demand floor. | autoscaler: LK primary (LK>EC2); allow_money_on_latchkey=true; GH only for resource-light jobs; EC2 ondemand_floor=0, burst-only |
| 57 | **One core `--approve` cascades to the pinned plugin bumps. OWNER-LOCKED 2026-09-20.** The owner approves a busbar-core release ONCE at qa/main; the core release requires each default-pinned plugin's qa to be green against it, and plugin repos promote independently (THE DESIGN §9) — no separate per-plugin-repo human approval. One gate, not twenty. | single owner --approve on core; core release blocked unless every default-pinned plugin's qa is green; no per-repo approve gate |
| 58 | **Doc policy: one canonical doc per topic, edited in place, delete-don't-supersede — ALL docs. OWNER-LOCKED 2026-09-20.** Exactly one canonical document per topic; edit it in place; a new doc is allowed ONLY if the old one is deleted. Never leave an outdated/superseded doc lying around (stale docs are how the ledger rotted — a-superseded-by-b-superseded-by-c). Applies to EVERY doc — design docs, READMEs, playbooks. | no superseded/duplicate docs; one canonical doc per topic; a new doc requires the old deleted in the same change |

| 59 | **The cell safety-net is locked policy; every accepted-gap needs explicit owner sign-off. OWNER-LOCKED 2026-09-20.** The oracle tracks every expected result-cell and flags any that silently vanishes (a golden SKIP is never a pass; the owed-baseline regression gate stands). Adding an entry to the accepted-gaps register ALWAYS requires explicit owner approval — an agent may NEVER self-approve a gap under the owner's name (same bar as a money-byte divergence). | owed-baseline/cell-vanish gate active; accepted-gaps entry requires owner sign-off; agent-added gap = RED |
| 60 | **"2× fresh audit" = loop the full audit to zero-found on a RE-RUN, never trust one 'done'. OWNER-LOCKED 2026-09-20.** Done means: run the full `/codeaudit` over all code → fix to 0 issues → run the full audit AGAIN → still 0. Repeat until a fresh pass finds nothing; a single pass that says "done" is not trusted (the skill already fans sonnet+opus but does not catch everything first time). Convergence = two consecutive clean full passes. "All code" means the code that ships: code being deleted or folded is not audited (owner, ~2026-09-19: *"don't audit what we delete"*); it is audited in its folded home. | ship/done gate requires two consecutive clean full-audit passes (re-run finds zero), not a single pass |
| 61 | **Force-push rule: own working branches only, `--force-with-lease`, never a shared branch. OWNER-LOCKED 2026-09-20.** An agent may force-push ONLY its own `land-*`/`keep-*` working branches, always with `--force-with-lease`, and NEVER a shared branch (`dev`/`qa`/`main`) or a repo the owner doesn't own. | force-push limited to own land-*/keep-* branches with --force-with-lease; shared branches never force-pushed |

| 62 | **A mid-stream cut is NOT a refund — the customer pays for what actually streamed. OWNER-LOCKED 2026-09-20 ("LOCKED AGREED").** If a live/streaming request is cut off mid-answer (breaker, disconnect, auth revoked, timeout), busbar bills for what was actually delivered up to the cut — it does not refund or zero the charge. Consistent with #43/#45: the plane reports the units actually streamed; the ledger records them; the money view prices them. A cut is an interruption, not a reversal of incurred cost. A stream served on a fallback lane bills like a primary-lane stream (owner, 2026-09-04: `stream_options.include_usage` on the degraded/fallback path, registered `improvement`, money-affecting). | mid-stream cut bills streamed units to the cut point; no refund/zeroing on cut; plane reports actual streamed units |

| 63 | **Hook behaviour is BYTE/BEHAVIOUR-IDENTICAL to 1.5.5 — 1.6.0 changes only the crate home. OWNER-LOCKED 2026-09-20 (owner-reviewed).** No change to WHERE hooks fire (the four points: request/inbound-rewrite, candidate, routing/decide, response/read-only tap), to fire-once semantics (per request — per gate on rewrite, per hop on decide — NEVER per token), to fail-closed handling (a broken/unparseable reply REJECTS the request; strictest wins: reject > restrict > abstain > allow), or to the grant model (two dials defaulting to nothing: `argument` none/ro/rw + `identity` none/ro; never sees secrets/tokens/price tables). The ONLY 1.6.0 change is relocation to a plugin `busbar-hook-<name>` in its own repo (`busbar-hook-ranking`, #34/#39) computing no money (#43); a plane calls hooks through the completion-style `hook.call` host service (THE DESIGN §2). Oracle proves hook behaviour unchanged. As in 1.5.5 (owner, 2026-09-04): a pre-forward auth refusal (401) on a hooked pool fires the completion tap once, with the synthetic outcome `rejected_by_auth` and the protocol-native status; every other pre-forward refusal (403/429/413/404) never taps. | hook fire-points/fire-once/fail-closed/grants identical to 1.5.5 (oracle byte-green); only the crate home moves to busbar-hook-<name> |

| 64 | **Parity packets #3 (NEUT-U-auth) and #4 (BOOT-135) = APPROVED. OWNER-LOCKED 2026-09-20.** #3: the `auth:` unknown-key error's "expected one of" list gains `operator_pub` (a real new 1.6.0 auth field, D38 operator-sealing); exit code + main error unchanged — approved, oracle re-blesses `neutrality|NEUT-U-auth|validate`. #4: a boot-time archive-read error's embedded THIRD-PARTY library text changed; busbar's own format string + exit code unchanged — approved (twin of the already-accepted BOOT-141), oracle re-blesses `boot.refusal|BOOT-135|boot`. Packets #1/#2 (PutConfigSettings restart-defer) = root-fix bugs, not sign-offs; #5 (boot-lines port) = harness flake. | oracle re-blesses exactly NEUT-U-auth + BOOT-135 cells; #1/#2 fixed at root; #5 stabilized |

| 65 | **Zero-trust plugin model: every KernelSeal must be cryptographically UNFORGEABLE before 1.6.0 ships. OWNER-LOCKED 2026-09-20 (hardens #40; a signed plugin is still not trusted to bypass a seal).** A validly-signed plugin passing the loader is NOT trusted to forge a capability seal. TODAY the picture is mixed: the SECRET-accessor seal (raw secret bytes) IS sealed/shipped (`contract-secret-seal`), but the DESTINATION/capability seal (`VerifiedDestination`/KernelSeal) is **forgeable in-process** (a doctest constructs a fake one) — undercutting #40. 1.6.0 makes ALL kernel seals unforgeable (constructible only by the kernel; no public/forgeable constructor, RED-provable) as a CUT requirement, not a follow-on. Handles are owner-scoped: a `ConnId` or auth object is checked against the plugin instance that owns it on every op, and first-party means a root-manifest grant (THE DESIGN §5, §6). | no public/forgeable KernelSeal constructor (incl. VerifiedDestination); a gate proves no non-kernel code can mint a seal; ships blocking |

| 66 | **Money is UNITLESS abstract cost — no currency type, no symbol. OWNER-LOCKED 2026-09-20 (clarifies #44; matches 1.5.5 "abstract cost units, busbar attaches no currency").** The rate card is plain numbers (e.g. `1.87` per output token); busbar attaches NO currency and NO symbol. There is no default reporting currency and no "unpriced-currency" concept — pricing is just numbers from the rate card. (Reverses an earlier USD-default suggestion.) | no currency type/symbol anywhere in the money path; rate card + ledger + views are unitless numbers |
| 67 | **`predev` is the permanent WIP branch; `dev` is release-train-write-only. OWNER-LOCKED 2026-09-20 (amends #32).** All work-in-progress lands on `predev` in every repo; the release train is the ONLY writer of `dev` (then `dev→qa→main`, #32). Keeps `dev` always-promotable. | WIP lands on predev; dev is written only by the train; branch protection enforces no direct dev writes |
| 68 | **The conformance MUST-set is a HARD gate before dev-green. OWNER-LOCKED 2026-09-20.** No dev-green until the conformance suite (the MUST set) is landed and passing; nothing ships on stubbed MUSTs (this requires landing the `integration/conformance-b` stack). | dev-green blocked until conformance MUST-set is landed + green; no stubbed MUSTs at dev-green |
| 69 | **Cross-protocol error translation to the client's format = 1.5.5-identical. OWNER-LOCKED 2026-09-20.** When a client speaks one protocol and busbar routes to an upstream speaking another, an upstream error is remapped through busbar's neutral form back into the client's protocol format — same as 1.5.5 (oracle byte-green). The dialect's `error_map` (#51) feeds this. | cross-protocol error remap = client's format, byte-identical to 1.5.5 (oracle-gated) |
| 70 | **Plugin authenticity is unforgeable; default signed-only; admin explicit opt-in for unsigned/third-party. OWNER-LOCKED 2026-09-20 (affirms #40).** A dropped-in plugin is cryptographically signed; the loader verifies it against busbar's EMBEDDED release key (busbar-signed = zero-config verify) or an allowlisted third-party ed25519 publisher — a busbar-signed plugin cannot be forged. DEFAULT: signed-only (`plugins.trust.allow_unsigned=false`, `allow_third_party=false`, `config.yaml:428`); the loader refuses unsigned/non-allowlisted. Admin may DELIBERATELY relax via `allow_unsigned`/`allow_third_party` + publisher allowlist; `min_versions` gives anti-downgrade floors. Distinct from the in-process KernelSeal (#65). | loader refuses unsigned/non-allowlisted by default; busbar release key embedded; admin opt-in toggles honored; min_versions anti-downgrade |

| 71 | **Ledger event = the plane's raw usage COUNTS per class; pricing is read-time; seals are zero-cost — the hot path carries no money math. OWNER-LOCKED 2026-09-20 (makes #43/#66 concrete + a perf invariant).** A plane's whole money obligation is to emit ONE fact per unit: raw counts keyed by plane-declared class strings — e.g. `{output_tokens: 27, input_tokens: 42, cache_read: 3}` for llm, `{seconds: 12}` for streaming, `{frames: 400}` etc. The ledger APPENDS those counts verbatim (write-behind, per-unit — NOT per-token). The MONEY VIEW computes `Σ count × rate_card(class, card_at(ts))` only at READ time, in the kernel — never on the serving path. PERF INVARIANT: (a) capability seals/tokens are zero-sized compile-time proofs — `&KernelSeal` etc. compile to nothing, 0 ns on the hot path; (b) no rate lookup / multiply / currency math runs on the request path; the per-token inner loop (plane+transport POD lane, #30) touches no money. | plane emits counts-per-class only (no price); ledger append is write-behind per-unit; pricing computed at read; no money arithmetic or non-ZST token on the per-token/hot path (perf gate) |

| 72 | **The kernel unit is a 10-stage typestate pipeline; each stage's pass is the key the next stage requires. OWNER-LOCKED 2026-09-20 (names the ONE concept behind "seals/tokens/stamps").** The ten stages, in order (`busbar-caps/src/step.rs:42`): **Arrival → Decode → Authenticate → Verify → Approve → Admit → Route → Meter → Audit → Encode.** Each stage, on passing, produces a zero-sized typed **pass** (`UnitToken<Stage>`) that the NEXT stage takes as input — so stages cannot be skipped or reordered (compile-enforced), and a refusal produces no pass so the chain stops fail-closed (drops to Audit/refuse). There are exactly TWO flavors of the one idea: (1) **stage-pass** — one per stage; (2) **capability grant** — a few extra proofs authorizing a specific privileged action, minted at the stage that earns them: `VerifiedDestination` (dial this upstream, minted at Verify, required by Route), `EgressAuthToken` (sign outbound), `LedgerToken`/`ExitToken` (write the book, at Meter/Audit). Root: `KernelSeal` mints any of them and nothing else can (#65). All are zero-cost at runtime (#71). | pipeline order Arrival→…→Encode enforced by per-stage pass tokens (compile-time); refusal = no pass = fail-closed; capability grants ride Verify/Admit/Route/Meter; only KernelSeal (kernel-only, #65) mints |

| 73 | **Capability-proof vocabulary unifies to two words: `Pass` (per stage) + `Grant` (per privileged action). OWNER-LOCKED 2026-09-20.** The current type-name zoo (`KernelSeal`, `UnitToken<Stage>`, `AdmitToken`, `VerifiedDestination`, `EgressAuthToken`, `LedgerToken`, `ExitToken`, `HoldCell`, …) renames to ONE scheme: a per-stage **`Pass`** (the 10 stage-passes, #72) and a per-capability **`Grant`** (dial/sign/write-money/…), both minted only by the kernel root (still `KernelSeal` or renamed at implementation, kernel-only per #65). Same zero-cost mechanism, far fewer terms. Exact rename map proposed at implementation for owner ok; the Pass/Grant proof types land in `busbar-contract`/`busbar-kernel` (`busbar-caps` is killed/folded, #37). | capability-proof types are exactly `Pass<stage>` + `Grant<capability>` + one kernel root minter; no other proof-type names survive; rename map owner-approved |

| 74 | **Per-call binding of capability proofs: cheap generation-id in-process, kernel-MAC'd handle at the untrusted ABI. OWNER-LOCKED 2026-09-20 (closes the runtime-binding gaps under #72/#65).** IN-PROCESS (trusted kernel stages): keep compile-time typestate + stack-scoping as the order proof (#72), PLUS a per-request **generation id (`u64`)** carried in the unit context that stages compare (~1 ns, NO crypto) — makes cross-flow binding explicit and catches a stray/stored pass without any hot-path crypto cost (#71 holds). A full keyed-hash chain across all 10 stages was REJECTED (10× HMAC/request = hot-path tax on trusted-vs-trusted code). AT THE UNTRUSTED PLUGIN ABI (where a plugin can store/replay a handle): the handle a plugin holds is **kernel-MAC'd, bound to a per-request kernel secret + generation** (AACS-like keyed derivation, NOT a plain hash — plain hashes are forgeable); the kernel verifies it on every ABI call, so a plugin cannot forge, reuse across flows, or replay a stale handle. ONE check per ABI crossing (per-request, NOT per-token) — off the hot loop. Realizes the #65 zero-trust posture at runtime. | in-process: per-request u64 generation compared by stages, no crypto; ABI handle = kernel-MAC(per-request secret+generation), verified each crossing; forged/replayed/cross-flow handle ⇒ reject; no per-token crypto |

| 75 | **Channel-2 (plugin→OS/RAM) residual is ACCEPTED because trust is first-party-only by default; drop-in hijack is impossible without an explicit admin opt-in. OWNER-LOCKED 2026-09-20 (risk-acceptance rationale for #55/#40/#70).** The capability model (Pass/Grant #72–#74) does NOT sandbox a plugin from the OS/process RAM — a native cdylib that ignores the ABI could read secrets/the MAC key. That hole is UNREACHABLE by an outside attacker: default trust is signed + FIRST-PARTY-ONLY (loader refuses unsigned/non-allowlisted, #70); running a 3rd-party/untrusted plugin requires a DELIBERATE admin opt-in (`allow_third_party`/`allow_unsigned` + publisher allowlist). So "drop a hostile .so in and hijack" cannot happen by default. RESIDUAL (named, accepted): supply-chain / signing-key compromise of an explicitly-trusted publisher — signing proves origin, not good behavior. A second named residual, data-plane (owner residual-risk register, on or before 2026-09-04): any token-exchange principal mints `user:*` template instances without a second approver, unbounded when `max_auto_provisioned_groups = 0` (the default) — possibly of uncapped leaves, stated as such. This is the standard native-plugin trust model (nginx/Postgres/kernel modules); posture B (WASM/OS sandbox, #55) would further contain it and is not part of 1.6.0 (owner-tabled), and is not a cut blocker. | default posture first-party-only (loader refuses untrusted); 3rd-party requires admin opt-in; channel-2 residual documented + accepted; posture B tabled |

| 76 | **Lossless carry / zero-waiver is the product's core differentiator. OWNER LAW (genesis, `4f245182`).** busbar carries EVERY field 100% losslessly across protocols — "we don't leave things on the floor" is what we sell. Implement all and translate all where possible; an un-looked-at field is a MAJOR violation, not an acceptable gap. Cross-protocol no-equivalent = drop + warn + covered by a test; wrong-typed input = a native ingress error envelope (never a silent coercion). Waivers are very minimal — each a recorded, tested exception, never a silent drop. Owner: *"We sell this product as being able to carry every field 100% losslessly … 307 fields un looked at is major violation"*; *"implement all and translate all where possible, thats literally the product"*; *"IR completion is key. we don't leave things on floor, its our differentiator."* Client headers: an allow-listed `anthropic-beta` / `anthropic-version` rides to a matching `anthropic` upstream and `OpenAI-Beta` to a matching `openai`/`responses` upstream, scoped per egress dialect so nothing leaks across protocols; every other client header is dropped (owner, 2026-09-04). | IR/field-coverage: every source field mapped-or-(dropped+warned+tested); waiver register minimal + tested; wrong-typed ingress → native error envelope |
| 77 | **Money-model core invariants (complements #42/#43/#44/#62/#66/#71). OWNER-LOCKED (`f9c0fb91`).** (1) **Pricing keys live on their OWN noun, never on a plugin/plane** — money/ledger keyed by `(principal, meter_class[, lane], units, timestamp)`; money types hold NO plugin/plane field, so per-plugin/per-plane pricing is UNREPRESENTABLE (not merely banned). "Different price per plane" = planes DECLARE different meter-class strings (llm `tokens`, mcp `calls`, a2a `hops`, streaming `audio-seconds`) an operator prices — same capability, zero plugin identity. (2) **ONE sealed FACTS line per unit, written ONCE at the END** — never edited; no early accrual, no refunds, no adjusting lines. The plane is the one decider: it reports units (and fee units) as they happen; running reports are checkpoints, never lines; the kernel writes what it is told and adds no floor (THE DESIGN §7). (3) **Price is NEVER stored — money is a read-time conversion** (rate rows only ever ADDED; retroactive repricing is free, dated view #dated-card/S0). (4) **Classes are STRINGS declared by the plane** (data); a flat fee = the `request` class (#44). (5) **Unpriced class = BOOT REFUSAL** when billing is on; free is an EXPLICIT zero row, never silent (#42). One scoped exception (owner, 2026-09-27): an absent reserved token tier on a rate-card entry prices at 0, as 1.5.5 read it; classes under `units:` still refuse. (6) **Budgets** enforced over any operator window ($/min,$/hr,$/week) per key/group via in-memory holds released when the line is written, hydrated from store on restart; `concurrent` stays a limit, not a budget. `admission: exact` (default) or `estimate` — one check at admit (THE DESIGN §7). (7) **`on_exhaustion` = finish-unit (default) | cut-stream** — a cut is NOT a refusal (#62): it settles a closed Abort arm carrying class+cap+delivered-qty, costs one row. That is the ledger. The client is told: where the protocol has a place to say so, a cut ends the stream with an error frame naming budget exhaustion, never a silent end (owner: *"A cut IS a reason the client is told"*; THE DESIGN §7). Defaults `exact` + `finish-unit`; a non-streaming unit overshoots by at most one request. (8) **Integer-only math, NO floating point on any money path** (the 1.6.0 model is UNITLESS — no currency/minor-units, #66); new per-N-units terms use banker's rounding (#44); the legacy 1.5.5 path reproduces its existing rounding byte-identically. (9) **8-verb admin surface** — the dispute/overdraft/adjustment verbs (`adjust, resolve_slice, resolve_dispute, set_dispute_max_age`, overdraft-ceiling) are REMOVED. The admin API is dumb (owner, 2026-09-08): one admin tier; roles, who may call what and whether a change wants a second pair of eyes live in the calling application. `set_operator_key`, `set_escrow`, `set_dual_control`, `approve` and `export_keyset` do not exist, and no verb carries dual control, escrow or operator signatures. Each verb is a plain scoped verb authorized by the per-verb allow-list on the admin token (`verbs: [ … ]` or `verbs: "*"`; `read-only` and `full` stay the 1.5.5 shorthands); the replay cache keyed `(actor, verb, idempotency-key)` is a mechanism, never a control. A kernel verb binds over HTTP as `<kebab-case-verb>` under the admin prefix — POST for every mutating verb, GET for `verify` and `plane_facts` (CG-56, 2026-09-05). (10) **"No flags"** — a single group-commit durability mode. | money types carry no plugin/plane field; one sealed facts-line per unit written at end; price never stored (read-time view); unpriced⇒boot-refusal (billing on); integer-only + banker's; 8-verb admin surface (no dispute/overdraft verbs); oracle byte-green on the money path |

| 78 | **CI cost model = job-tier-by-cadence + $100 hard cap; mutation testing is optional. OWNER-LOCKED 2026-09-20.** Runner spend is priority-1 (the whole point of the autoscaler). Latchkey bills PER JOB-MINUTE, rounded up per job; idle/warm/parked runners are FREE (LK's always-on warm-small baseline is theirs, not billed) — so "0 jobs = $0" is already true; the lever is job-minutes, not infra. **Hard cap $100/period** total infra; **$50 soft-alarm, $80 review** → on breach find the top workflow and cut its trigger/right-size. Cost driver was measured: gate-mutants = 69% of runner-minutes, 89% of minutes on `latchkey-xlarge`. **Job tiers by cadence (a job runs where it belongs, once):** (a) **push** (integration/**, dev, qa + PR) = `ci` only — fmt/clippy/build/test + the required gate battery (structure-lint, construction-gate, ship-ready, shadow-oracle) = fast dev feedback; (b) **qa gate** (push qa) = conformance (a2a/mcp/voice), codeql, security, release-stage — the exhaustive "may this ship" set, run ONCE per promotion; (c) **main** = release/verify only, NO test-gates (qa→main is same-SHA fast-forward, so qa's checks ride the commit — re-testing on main is duplicate spend); (d) **manual** = gate-mutants (workflow_dispatch only); (e) **scheduled/reusable** = monthly-refresh/oracle-store-cells/security-weekly, and workflow_call reusables. **Mutation testing (gate-mutants) is TEST-ENHANCING, not release-breaking** — it measures whether the test suite catches injected bugs; it finds no product bugs and hardens no release. So it is MANUAL-ONLY and 100% OPTIONAL: REMOVED from qa+main branch protection (`scripts/ci-branch-protection.sh`) and the `ship-ready` gate no longer owes/reads a mutation verdict (`xtask/src/gates/ship_ready.rs`). **Nothing does the same job twice** — `keep-proof` was ~75% a re-run of `ci` on the same commit, so it is DISPATCH-ONLY now (its one unique capability, the hand-back-SCOPED shadow-oracle, stays on demand). The turnstile RE-RUNS the battery itself (never reads CI statuses), so it is the promotion arbiter and CI is per-push feedback — that macro overlap is by design. Workflow-file RENAMES to a cadence prefix (`push-`/`qa-`/`manual-`/`sched-`/`reusable-`) ride the W6 atomic rename wave (#34), NOT piecemeal now (name/path renames break required-check names, `workflow_run` links, cosign identity, and cross-repo `uses:`). **Where gate logic lives (owner, 2026-09-06):** in Rust, in `xtask`, as `cargo xtask gate <name>`; a workflow step calls one command per gate and holds no gate logic; no new shell or Python script is added to the repo, and the existing ones convert (#80 takes the oracle's Python to zero). | LK bill ≤ $100/period (soft-alarm $50); ci=push-only, conformance/codeql/security=qa-only, no test-gate on main, gate-mutants=dispatch-only + not a required check + not owed by ship-ready; keep-proof=dispatch-only; cost-watch checks the LK Cost-Analysis each period |
| 79 | **Rate cards are a DATED HISTORY; a posting prices against the card IN FORCE when it arrived. OWNER-LOCKED 2026-09-22 (resolves the #44 "rate-card history" park; makes "latest" precise in #42/#43/#71).** "Price against the latest rate card" means the latest card whose `effective_from` had arrived at the posting's instant — NOT the latest card ever authored. Cards are APPLIED WITH AN EFFECTIVE DATE. Owner's worked example: a user signs PAYG at 10; three months later signs month-to-month and the rate becomes 5; later signs a yearly prepaid and it becomes 1. The first three months keep pricing at 10 forever. **Publishing a new card never reprices the window before its `effective_from`.** (RULED 2026-09-27: the PostConfigApply register entry adds the `norm.rules` class and carries the corrected rationale.) The resolution key is the posting's own arrival instant (`arrived_ms`) against the dated history — NOT a version stamped into the posting, so history is recoverable backward, not merely forward; `rate_card_version` stays pure reporting provenance (#44: VISIBLE on usage/audit), never the pricing input. A **back-dated correction** (an entry whose `effective_from` lies in the past) DOES reprice exactly the window `[effective_from, effective_until)` — that is the sanctioned repair path for "the ratecard was wrong" (Part 1: money is never wrong, the ledger or the ratecard is wrong), it is an APPEND and a signed admin act, never an edit. **A booked line is never rewritten** (owner, 2026-09-06: *"think banks. A booked line is never rewritten."*): a correction is an appended, journaled, dated entry, so the original figure and the corrected one are both on the record; a money read can be pinned to a history snapshot (`?as_of=<history_seq>`) so an invoice cut at that snapshot regenerates byte for byte; and a correction may change what a served unit is billed but never re-decides its admission — budgets, caps and holds decided with the card in force at the time. Billing evidence is purged only by an explicit, audit-logged operator action and never by an automatic sweeper (the contract's rule on `RecordStore`'s metering purge, `busbar-contract/src/records.rs`); the memory store's 31-day in-RAM retention is the 1.5.5 behaviour and stays (#9). Engine already exists and is reachable: `crates/busbar/src/root/kernel.rs:262` (`effective_from`), `:291` (window recompute), `root/units_admin/mod.rs:679` (signed back-dated entry). The owed work is that `GET /admin/usage` does not consult it — it reprices flat off the current card. | `GET /admin/usage` resolves each posting through the dated history by `arrived_ms`, not the newest card; publishing a forward-dated card leaves every prior posting's price byte-identical; a back-dated correction reprices exactly its window and nothing outside it; no pricing path reads `PostingStamp.rate_card_version`; no correction rewrites a booked line; a read at `as_of=<seq>` taken before a correction is byte-identical after it; a correction never turns a served unit into a refusal |
| 80 | **The oracle is 100% Rust, 0% Python — INCLUDING the corpus generator. OWNER-LOCKED 2026-09-22 (closes the oracle's Divergence 1).** "0% Python" was scoped to the 12 files in `GetBusbar/busbar-oracle` (5,726 lines); it also binds a **13th, uncounted file inside busbar itself** — `testing/shadow-oracle/cells/__init__.py` (1,825 lines), the authoritative generator that WRITES the 2,318-entry `cells.json`. The Rust port today covers only the VALIDATOR half (`busbar-oracle cells --check`: duplicate-id + floor checks over the committed corpus); the GENERATOR half is unported, so corpus drift is not merely passing — **it is not being checked at all**. **MEASURED 2026-09-22 — the diagnosis held, the remedy was cheaper than scoped:** a byte-identical Rust port already existed (`busbar-release`'s `crates/busbar-release-corpus`, commit `fbdf19b`, 2026-09-18) with its own insertion-order JSON value type and CPython `json.dumps(indent=2)` writer; what was missing was the WIRING — the judge binary had no `--generate` verb and `cells --check` never called the generator, so the drift hole was open exactly as described even though the code to close it was sitting there. Closed by wiring, not by re-porting. Python DELETED; Rust, CPython and the committed corpus all agree on sha256 `0c84a376…`; the committed corpus was NOT stale. RULING: port the generator into `busbar-release-oracle` beside the validator, prove it emits a **byte-identical** `cells.json` differentially against the Python (same standard the `apply-mutation` port met over 213 real mutations), then DELETE the Python. Rejected alternatives: keeping it as a declared out-of-band data-authoring step (leaves one Python file in busbar forever and drift unverified), and promoting `cells.json` to hand-maintained source of truth (loses programmatic regeneration of 2,318 cells). The one permanent, documented python3 boundary that SURVIVES is `testing/shadow-oracle/scripts/apply-deferred-decisions.py` (`recorder/live.rs:1856`), which is the product's own migration tool, not the judge — same class as the `jq` dependency. | `cells/__init__.py` deleted; `busbar-oracle cells --generate` emits the committed `cells.json` byte-for-byte; a differential test runs both and asserts equality; `git ls-files '*.py'` under `testing/shadow-oracle/` returns ONLY `scripts/apply-deferred-decisions.py` (the one surviving boundary named in this row's body); drift-check runs in CI |
| 81 | **UNIT COUNTS ARE EXACT FRACTIONAL QUANTITIES — never rounded, never refused, never binary floats. OWNER-LOCKED 2026-09-22. AMENDS #77(8) and #44; a KNOWING, SIGNED divergence from 1.5.5.** Owner's words: *"27.5 imo is 27.5… you spent 27.5 tokens not 27 not 28."* A usage count is a MEASUREMENT and the measurement is whatever the plane observed. `27` is 27; `27.0` is 27; **`27.5` is 27.5**; `0.001` is 0.001. No rounding up, no rounding down, no banker's rounding, no refusal on ingest. **#77(8) is amended, not reversed:** the ban on BINARY FLOATING POINT (`f32`/`f64`) on any money path STANDS and strengthens — what changes is that the exact type is now DECIMAL, not integer. Reason the ban survives the ruling: `f64` cannot represent `27.1` (it stores `27.100000000000001421…`), because binary floating point holds only fractions with power-of-two denominators — so `f64` would break this very ruling on the next value. **REPRESENTATION: exact fixed-point decimal** — an `i128` mantissa at ONE fixed scale of 6 (micro-units) across every count and every plane: `27.5` is stored `27_500_000`, read back `27.5`. **RANGE — CORRECTED 2026-09-22 by measurement:** i128 at scale 6 holds ~1.7e32 in memory, but the LEGACY STORE WIRE caps it far lower — `legacy_usage.rs`'s `TierTokensDelta` fields are `i64`, so an ABI-2 store plugin tops out near **9.2e12 whole units**. Quote that number, not the i128 one, for anything that crosses the store ABI. **PARSING IS THE LOAD-BEARING DETAIL: read the JSON number's DECIMAL TEXT, never its `f64` value** (`serde_json`'s `arbitrary_precision`, or the raw token) — a count that transits `f64` has already lost exactness before any conversion can save it. `read_count_u64` (`crates/busbar-llm-codec/src/usage_count.rs`) is superseded by the decimal reader; its float branch exists only because `.as_u64().unwrap_or(0)` silently recorded float-spelled counts as ZERO and shipped that way in v1.5.5. **A value that will not fit the declared scale EXACTLY is a REFUSAL (#42), never a rounded guess** — money-sacred: busbar never invents a digit. Pricing stays `Σ count × rate` (#71) in exact fixed-point; a per-N-units division term still uses banker's rounding (#44), because a DIVISION can genuinely be inexact where a MEASUREMENT cannot. Unitless still holds (#66): scale is precision, not currency. **1.5.5 DIVERGENCE IS EXPECTED AND SIGNED** — oracle cells that moved because 1.5.5 truncated or zeroed a fractional count cite THIS ROW as their authority; the owner ruled *"if thats a change from 1.5.5 thats fine as its necessary."* | no `f32`/`f64` on any money path (gate, RED-provable); counts parse from decimal text, never through `f64`; `27.5` round-trips as `27.5` and `27.1` as `27.1`; a count that will not fit scale-6 exactly REFUSES; Σ over a million rows is order-independent and reproducible byte-for-byte **PERSISTED FORM (measured 2026-09-22):**no quantity**. **Zero existing chains are invalidated by a count-representation change.** (b) **The persisted surface is TINY:** twelve fields across four structs (`UsageLedger`, `TierTokens`, `MeteringRow`, and the wire twins), every one an LLM token tier or a request counter, all bare JSON integers; `usage_units` is 1.6.0-new (zero hits at v1.5.5) so **no ambiguous population exists in the field**. The single conversion point is `plugin-loader/src/store_adapter.rs:461`, inside a read-only run-once first-boot path. (c) **A RESCALE IS FORBIDDEN.** `api/src/usage_migration.rs:26-33` states its crash-safety proof: a mid-scan crash re-runs the whole scan, which is safe only because re-folding an already-folded row adds zero. **`× 10^6` is not idempotent** — run twice, get `10^12`. The protocol that is safe for the existing fold is unsafe for a rescale. (d) **THE FORM IS A DISCRIMINATOR**, the pattern this tree has already shipped three times — `AuditEntry.scheme` (`legacy/entry.rs:95-120`), `TaskEventRow.digest_version` (`busbar-a2a/src/taskstore.rs:148-153`), `needs_legacy_usage_wire` (`legacy_usage.rs:34-40`). One `#[serde(default)]` field plus a branch at the read: ABSENT ⇒ whole units (the v1.5.5 shape), PRESENT ⇒ scale 6. Old rows self-identify; nothing is rewritten; out-of-tree ABI-2 binaries keep receiving exactly the four-tier whole-unit wire they receive today. (e) **COUNTS, CAPS AND RATES RESCALE IN ONE COMMIT OR NOT AT ALL.** `busbar-kernel-budget/src/decide.rs:334-349` and `kernel/src/governance/state.rs:1926-1941` compare counts against `tokens_cap`/`tokens_input_cap`, which are **unscaled operator config** — a one-sided change makes every limit wrong by 1e6. Likewise the price multiply (`kernel-ledger/src/cost/posting.rs:320-322`, `cost/rate.rs:435`, `kernel-budget/src/price.rs:113-118`) **overbills by 1e6** unless rates move with it; do NOT "fix" that by dividing — #44 permits rounding only on a per-N-units term, and a measurement is not a division. (f) **PARKED, narrow, and currently unreachable:** a genuinely fractional count destined for an ABI-2 store has nowhere to go — four `i64` columns cannot hold it, truncating violates #81, and refusing breaks a working deployment on upgrade, which `migration.rs:57-62` names as the one outcome a migration may not produce. It REFUSES (#42) pending an owner ruling. This cannot fire today: no provider has been shown to emit a fractional count on the wire (Cohere's spec renders `18.0` for the streaming `message-end` it bills from, but no capture exists). Also note `legacy_usage.rs:23-25` already silently DROPS any unit key outside the reserved four, so non-LLM plane counts never reach a published store at all — a separate, older defect. (g) **No gate protects this** — nothing inventories persisted-field representations (`field_inventory.rs` covers dialect wire only), so a scale mismatch between busbar and a published store plugin would not be caught. A gate is owed.  See the full derivation in the commit that landed this row. | a scale-discriminated row round-trips; a v1.5.5 row with no discriminator reads as whole units unchanged; the first-boot conversion runs once and is provably safe to re-run; caps/rates/counts scale in one commit (a test asserts a cap still bites at the same real quantity); an ABI-2 store receives byte-identical four-tier whole-unit wire; a fractional count bound for an ABI-2 store REFUSES rather than truncating |
| 82 | **The audit chain is SIGNED IN CORE at seal time; the admin API EXPOSES it for PULL; anchoring and publishing are CLOUD, not core. OWNER-LOCKED 2026-09-22.** Today the chain is tamper-EVIDENT but unsigned and unanchored, so it proves only the internal consistency of a file the operator fully controls. **CORE OWES (1.6.0):** (a) **sign at seal time, in the process that sealed it**, ed25519 over the digest `AuditChain::digest_of` already computes — a signature applied later by a receiver proves only that the receiver got those bytes, not that the node produced them, so this half CANNOT be added later without leaving every prior record unprovable; (b) three admin READ verbs — the **head** (seq, hash, signature, key id, wall), a **record range by seq** (fields + hash + signature, so a puller verifies the chain itself rather than trusting the answer), and the **public key set**; (c) **the digest recipe becomes published, versioned public contract** — the exact length-prefixed field order — because if only busbar can verify busbar's chain it is a claim, not evidence; (d) **head history is retained FOREVER, independently of record retention** — a head is ~100 bytes, a year of hourly heads is under a megabyte, and a puller offline while records were pruned must not lose that window's anchor. **CORE MUST NOT:** publish, push, hold a cloud credential, or open any outbound connection for this. PULL model: the node answers, it never phones home — works behind a firewall, and an airgapped operator can `curl` it. **CLOUD (a separate product, not this repo):** pulls heads, timestamps, counter-signs, publishes a third-party verification page. Anchoring is definitionally outside core — **a node cannot anchor to itself.** **THE RECORD IS ONE FIXED SCHEMA FOR EVERY PLANE** (owner, on or before 2026-09-04; THE DESIGN §1): who, what, when, outcome, amount, controls, integrity — never optional, never plane-chosen. The amount is counts plus the rate-card version, never a price (#43, #77(3)). Content — prompts, tool arguments, audio, transcripts — never enters the chain for any plane; content retention is an export plugin's job, into the customer's own sink under the customer's own retention. **CLAIM BOUNDARY, and it is load-bearing: signing ALONE does not close the gap.** An operator holding the signing key can rewrite the chain AND re-sign it; what defeats that is an externally-recorded head, which a rewrite cannot match. So self-hosted may honestly claim *signed and tamper-evident* — "prove it to yourself and your auditor" — and only an externally-anchored head earns *"prove it to a counterparty who trusts neither of us."* Do not let the marketing claim outrun which of the two is deployed. | records carry an ed25519 signature minted at seal time in-process; admin exposes head + range-by-seq + public keys, read-only; core makes no outbound connection and holds no cloud credential for audit; the digest field order is documented and a third-party verifier reproduces a known chain WITHOUT the busbar binary; head history survives a record-retention pass that prunes its records |
| 83 | **EVERY CRATE HAS A DEFINITION, AND MEMBERSHIP FOLLOWS FROM THE DEFINITION — not the other way round. CONTRACT = SHAPES, globally. OWNER-LOCKED 2026-09-22.** Owner's words: *"first define every crate, then answer these by asking what fits the definition. if nothing we discuss a new crate. if 2 crates have same or split definitions we fix by merging"* and *"contract to me is exactly that, the shapes of anything, so it's logical to live there… this is global. contracts = shapes."* **THE PROCEDURE, and it replaces argument-by-precedent:** (1) every crate carries a ONE-LINE definition of the KIND of thing that lives in it; (2) a file's home is decided by asking which definition it fits — never by where it happens to be, never by who wrote it; (3) if nothing fits, that is an OWNER conversation about a new crate, not an agent's judgement call; (4) if two crates share a definition they MERGE; (5) if one crate holds two definitions it SPLITS. **`busbar-core-substrate` is the worked example and the reason the rule exists:** it holds pure ABI-shaped value leaves AND runtime machinery (a SigV4 signer, an eventstream parser, an SSE proxy, a protocol registry) — two definitions in one crate, so it splits (see #83a). **CONTRACT = SHAPES** is the first definition fixed: `busbar-contract` holds the SHAPE of anything — the data and its wire encoding — and `busbar-kernel-ledger` holds the SEMANTICS, what the shapes MEAN and what may be done with them. That resolves #40's store-plugin problem: a plugin needs `PlaneRecord`/`UsageLedger`/`VirtualKey`'s shapes, not the ledger's rules, so the shapes move and the money one-book leaves every plugin's dependency closure. Every ABI shape lives only in `busbar-contract/src/abi/` (THE DESIGN §11.5). **THE DOWNSIDES, stated so nobody is surprised later:** (a) contract's surface ceiling (`contract_caps`, declared 5,652, measured 6,837 — `cargo xtask loc busbar-contract`) becomes the most-pressured number in the tree and will need honest raises, not exemptions; (b) contract is in EVERY plugin's closure, so anything landed there is compile cost for every plugin — a shape with a heavy dependency does not belong; (c) contract becomes the single most ABI-sensitive crate, where one shape change is a breaking change everywhere at once, which is an argument for getting shapes right rather than for keeping them scattered; (d) the line "shape vs semantics" is not self-evident for a type carrying validation — the test is whether the RULE could differ between two honest implementations (semantics) or whether every implementation must agree byte-for-byte (shape). | every crate in the roster has a written one-line definition; no two definitions overlap; no crate has two; a new file's placement is justified by citing a definition; `busbar-contract` holds shapes only — a gate proves no SigV4-class runtime machinery lands there |
| 84 | **A KERNEL CHANGE MUST NEVER FORCE A THIRD-PARTY PLUGIN TO REBUILD. The SDK is the plugin surface; its closure is SHAPES ONLY; the ABI version is the sole compatibility promise. OWNER-LOCKED 2026-09-22.** Owner: *"a kernel change shouldn't mean all 3rd party plugins need updating, it would be a nightmare"* and *"plugins need to not be forced to change often."* **MEASURED, and the nightmare is LIVE:** every plugin in the tree depends on `busbar-plugin-sdk` + `busbar-api` — **not** on `busbar-contract` — and the closure is `plugin → plugin-sdk → busbar-api → busbar-kernel-ledger → busbar-contract`. **A third-party store plugin transitively links the money one-book.** Change a ledger type and every third-party plugin must rebuild, even though nothing it names moved. **THREE LAYERS INSULATE A THIRD PARTY, and only the first is absolute:** (1) **the C ABI** — a dropped-in `.so` links SYMBOLS, not Rust crates, so a kernel change that does not move the `repr(C)` layout cannot reach it; this is the strongest guarantee busbar has and #3 already provides it; (2) **the SDK's compile-time closure** — for a plugin built from source, what it LINKS is what can force a rebuild; (3) **the ABI version** — a third party pins "I implement store ABI v5" and nothing short of bumping 5 may break them. **TODAY LAYER 3 IS DISHONEST:** a plugin can compile against `STORE_ABI(5)`, touch nothing that changed, and still break, because the topology links semantics the version does not cover. The version promises a stability the crate graph does not deliver. **THE RULE:** a plugin's compile-time closure is exactly `busbar-contract` — the SDK merged into it (#33/#38), shapes only (#83). **Nothing on the plugin path may link a crate holding SEMANTICS** — not the kernel, not the ledger, not `busbar-api`. **`busbar-api` is the villain**: it is the single crate dragging the ledger onto the plugin path, which is the real reason #35 retires it. **THE WITNESS, and without it this row is only a wish:** a test that builds a plugin against a PINNED OLDER SDK and asserts it still loads. "We do not break third parties" must be checkable, not aspirational. **STRENGTHENED BY THE OWNER, same day, and this is the real target:** *\"the ABI was meant to isolate plugins so they never used any `busbar-*`\"* / *\"plugins can only speak json or memory\"* / *\"they shouldn't need or HAVE any imports of other crates.\"* So the rule above is not strong enough. **THE PLUGIN CONTRACT IS A SPECIFICATION, NOT A CRATE.** One ABI per kind, all on the memory ABI (THE DESIGN §11.1–§11.2). ~~Two lanes, per #3: (i) **JSON lane** — a published SCHEMA; the plugin takes bytes, parses them with whatever it likes, returns bytes; zero busbar imports, genuinely; (ii)~~ (SUPERSEDED 2026-09-27 by THE DESIGN §11.1) **MEMORY** — a published `repr(C)` LAYOUT plus an ABI version, shipped as a **generated header** (a `.h` for C/C++/Zig authors, a generated `.rs` snippet for Rust authors), **not as a linkable crate**. That is how libc and Vulkan work: you ship a header, not a library. **`busbar-plugin-sdk` therefore becomes OPTIONAL CONVENIENCE for first-party ergonomics, never a requirement** — a third party may ignore it entirely and talk the published spec. **THE FINDING THAT MAKES THIS URGENT: no plugin built this way has ever existed.** Every plugin in the tree — including all five examples (`auth-static-plugin`, `store-example-plugin`, `secret-example-plugin`, `hook-test-plugin`, `export-example-plugin`, `plane-example`) — depends on `busbar-plugin-sdk`. The zero-import path the ABI was designed for has never been demonstrated, so it is UNPROVEN, not working. Build one and it becomes the acceptance test. **FINAL FORM, owner 2026-09-22 — and it MERGES rather than splits:** *\"plugins use sdk, sdk uses nothing busbar-*\"* and *\"only when a new sdk is released should plugins update — that feels normal.\"* So the rule is two lines: **(1) a plugin's busbar closure is EXACTLY `busbar-contract` — one crate; (2) that crate's own busbar closure is EMPTY.** A plugin updates when, and only when, a new SDK ships. (1.6.0's SDK is that event, once: no published 1.5.5 JSON-contract plugin loads and a third party rebuilds against it — an owner-signed break, THE DESIGN §11.8. After it, a change to one kind's ABI rebuilds only that kind's plugins, §11.2.) That is a normal, announced, expected event — the same relationship every good SDK has with its users. What is NOT normal, and is what busbar has today, is that one dependency transitively dragging the kernel's money ledger. **CONSEQUENCE UNDER #83: `busbar-contract` and `busbar-plugin-sdk` SHARE A DEFINITION — \"the plugin contract\" — so they MERGE (#83 step 4), they do not split.** One crate, zero busbar dependencies, holding the shapes in fixed C layout under `src/abi/` (~~BOTH encodings (JSON schema + `repr(C)`)~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.1) plus the author-facing ergonomics. The kernel depends on it (the kernel implements the host side of the contract, which is the right direction); plugins depend on it; nothing else is in the closure. `busbar-plugin`'s ABI declarations and the plugin-facing half of `busbar-api` fold INTO it; `busbar-api`'s ledger edge dies because ledger SEMANTICS stay in the ledger (#83). **This SUPERSEDES #84a — do not split `busbar-contract` into a family.** The earlier split reasoning (~8,700 lines no plugin references) was measuring the right problem and reaching for the wrong instrument: the fix is that the non-plugin two-thirds (caps, grammar, transport registry) were never the plugin contract and leave, not that the contract fragments. Roster shrinks, not grows. Once the SDK re-exports shapes only, whether those shapes live in one crate or four is an INTERNAL matter a third party never sees — the split becomes tidiness, not protection. | **A PLUGIN WITH ZERO `busbar-*` DEPENDENCIES loads and serves, built from the generated C header alone (THE DESIGN §11.5)** ~~and the witness set COVERS BOTH LANES — one zero-dep plugin on the COLD/JSON lane and one on the HOT/POD lane, each on the single lane its kind is assigned (#30); never one plugin speaking both~~ (SUPERSEDED 2026-09-27 by THE DESIGN §11.1) — the zero-dependency reference plugin lives in a plugin repo and is the witness; `cargo tree` for it names no busbar crate at all; the generated C header is the only artifact an author needs (~~the published JSON schema and~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.1); a plugin built against another version of its kind's ABI is refused at load naming the rebuild, and a newer-than-host one is refused (RED-provable; THE DESIGN §11.8) ~~a plugin built against ABI vN-1 still loads under vN (RED-provable)~~; the ABI version is the only thing whose change may break a third party; first-party plugins MAY use the SDK but a gate proves at least one does not |
| 85 | **EVERY plugin response carries a uniform OBSERVABILITY ENVELOPE — `{ result, metrics[], diagnostics[] }`. One shape for every kind, not a per-kind bolt-on. OWNER-LOCKED 2026-09-22.** Owner: *"design the abi correctly and implement it. log changes from 1.5.5 but lets not accept a bad abi."* **THE DEFECT:** the export ABI is an effect-free one-way wire — `ExportResponse::Delivered` is a UNIT variant, and the cold tier has no host-callback vtable — so a sink cannot report the metrics it produced or the diagnostics it raised. That made the four `busbar-export-*` roster crates unbuildable: `file` increments `FILE_LOGS_ROTATED_TOTAL`/`FILE_LOGS_ROTATE_FAILED_TOTAL` and raises five registered diagnostics; `prometheus` renders a process-global recorder fed by ~57 kernel sites; `webhook`'s POST must ride the host's SSRF-guarded egress. None of it crosses the wire. **THIS IS NOT AN EXPORT PROBLEM — IT IS AN ASYMMETRY #3 FORBIDS.** The HOOK kind already has the back-channel (`busbar_api::hooks::HookStatus.metrics`, `crates/api/src/hooks.rs:326`), which the engine validates, bounds and folds into the exposition at `busbar-kernel/src/hooks/scrape.rs`. #3 says *"a plugin is a plugin — two universal rules, identical for every kind"*; one kind having a back-channel and another not is exactly the divergence that law bans. **THE RULE:** every kind's response is `{ result, metrics[], diagnostics[] }` — `result` is the kind-specific answer, the other two are universal. The plugin REPORTS; **the host VALIDATES, BOUNDS and DECIDES.** A plugin never mutates a host counter and never performs a host-owned effect (Part 4 Axis 3: the host always owns the SSRF/pin/breaker/meter chokepoint). **IT CLOSES A LIVE #11 HOLE:** today a COMPILED-IN plugin can reach the process-global `metrics` recorder while the same crate built as a dropped-in cdylib gets its own and silently loses the counters — so compiled-in ≡ dropped-in is asserted but FALSE. Under the envelope that reach is not representable, and the equivalence becomes true. **VERSIONING:** this bumps the ABI, and the bump is the honest outcome — a logged, signed 1.5.5 divergence beats a wire that cannot carry what a plugin did. Note the ABI surface is ALSO carrying eleven separate version constants (`STORE_ABI`, `TRANSPORT_ABI`, `EXPORT_ABI_VERSION`, `HOOK_ABI_VERSION`, `SECRET_ABI_VERSION`, `AUTH_ABI_VERSION`, `ABI_VERSION`, `ABI_MAJOR`, `ABI_MINOR`, `ABI_MAGIC`, `POD_VERSION`) — collapsing those to ONE number is the natural completion of #3 and of #84's *"plugins update only when a new SDK ships"* (a third party should pin one number, not eleven). (RULED 2026-09-27, THE DESIGN §10: the constants stay per ABI, each shipping as its v1.5.5 value + 1 — a constant new in 1.6.0 ships as 1 — ~~and each loader window admits the v1.5.5 value and the +1 value~~ (SUPERSEDED 2026-09-27 by THE DESIGN §11.8: the loader accepts only the current version of each kind); collapsing them to one number is not the ruling.) The envelope rides every reply of every kind ABI (THE DESIGN §11.2), and hook behaviour stays 1.5.5's on the memory ABI (§11.7). **Plugin logging rides this envelope too:** what a plugin logs becomes log diagnostics on its reply, and the host writes them to the plugin's own log file. The rule is stated once, in THE DESIGN §11.2, "Plugin logging". `/metrics` and `/metrics/hooks` are served by the prometheus export plugin through its own listener need (THE DESIGN §5). **THE ORACLE CANNOT SEE ANY OF THIS:** the 1.5.5 golden configures no file/webhook/otlp sink, and `ops.scrape\|metrics\|key` carries 15 families, none of them `busbar_file_logs_*`. Oracle-green here is necessary and nowhere near sufficient — the corpus is OWED cells that configure a file and a webhook sink, or this whole surface ships unwitnessed. **HOOKS ARE A FUNCTIONAL FIXED POINT while this lands (owner 2026-09-22: \"hooks have not changed in 1.6.0, one of the few things... if abi changes ok but functionally they have not been touched\").** Since this envelope is MODELLED on the hook kind, reshaping it must not move hook BEHAVIOUR. 1.5.5 is authoritative and readable — 24 hook paths **in the `v1.5.5` TAG, not in the current tree** — read them with `git ls-tree -r v1.5.5` — incl. `crates/api/src/hooks.rs`, `crates/busbar/src/hooks/{mod,plugin,wire,scrape}.rs` and the tests that ARE the contract (`crates/busbar/src/hooks/tests/{scrape_tests,tests}.rs`, `crates/busbar-llm/src/engine/tests/hook_opt_in_projection_tests.rs`). So: diff 1.5.5 against trunk FIRST and report any drift already there as a defect rather than preserving it; model the envelope on 1.5.5's `HookStatus.metrics`, not trunk's copy; and treat 1.5.5's hook tests as the acceptance suite — **if a 1.5.5 hook test cannot be expressed against the new shape, the SHAPE is wrong**: stop, never weaken the test. | 1.5.5's hook tests pass verbatim against the reshaped hook path; every kind's response carries `metrics[]` + `diagnostics[]`; the host bounds and folds them (hook's `scrape.rs` path is the model); a plugin reaching a process-global recorder is unrepresentable; a compiled-in and a dropped-in build of the SAME crate produce byte-identical `/metrics` exposition (RED-provable — this is #11's real test); the four `busbar-export-*` crates exist and their JSONL + exposition byte-match the compiled-in sinks; new oracle cells configure file and webhook sinks |

<!-- PENDING (execution, not decisions — all owner rulings captured in rows above):
MONEY SIGN-OFFS (all closed): S0 dated-card (F1/F2/F3, re-bless 3 cells) APPROVED (money model / dated-card
rows); parity packets #3/#4 APPROVED (#64); P1–P6 + empty-reply + Gemini-shortfall + wrong-provider +
voice-tool-args = BUGS to fix so bytes match 1.5.5 (plane reports truth, #43/#71), NOT sign-offs; audit
redaction = leave byte-identical (owner ruled). No money sign-off remains open.
STILL TO EXECUTE (no owner decision owed): (1) BRANCH RECONCILIATION — rows #41–#77 live on
land/conformance-turnstile-wiring; the land/decisions-consolidation ledger has its own #41–#45 with different
content — merge/renumber at fold; (2) architect-owned follow-ups: Pass/Grant rename map (#73), minimal-token
audit (#72/#73), transport roster + scheme-sets (#50/#51). Then execute Part 5's waves W0-W8 to DEV-GREEN.
DONE 2026-09-20: deleted 1.6.0-arena-model.md (it exists in NO commit on any ref — it lived only in a
working tree, so there is nothing to read and nothing to restore); added lossless-carry (#76) + money invariants (#77);
edit-in-place stale-row fixes (codec-crate #6/#18/#19/#20/#21/#34; planes 4→5 #3/#12/#17/#18/#19/#39; testkit
#33/#38; ABI-spec-home #33/#34/#35; Arena→Scratch #35; #49 schema; #38 testkit-feature removed; #73 caps home;
#35/#34 reordered). #28/#29 verified CORRECT as-is (MCP is proof-order; #28 already states plane-agnostic
loop-unify). -->

Commit authorship comes from git config (GitHub noreply). No AI attribution, ever.

---

# PART 3 — THE PLANE-EXTRACTION SEAM (LOCKED v4)

> *Absorbed verbatim from `1.6.0-plane-extraction-LOCKED.md`, which this document replaced and DELETED (`49ab4aca2`) — that name is history, not a path. Outranks Part 2 where they disagree.*


Owner ruling: **repr(C) plugin ABI NOW** — full dynamic-load parity with the tree's both-ways
conformance witnesses, `crates/plugin-loader/src/tests/{export,plane}_conformance_tests.rs` (#2).
(CORRECTED 2026-09-23: this ruling was recorded at `d154d1ab6` as *"full dynamic-load parity with
token-auth"*. `token-auth` has never existed as code at any tag, so the standard named was an empty
set — see #2 (the archaeology, 2026-09-23, searched every tag with each search controlled against a known-present string). The RULING is unchanged; only its
referent is made reachable.) Survived 3
adversarial rounds (r1: 9 spine-adjacent breaks fixed; r2: ~10 refinements, 0 spine breaks; r3: 0 spine
breaks, RR1/RR2/RR3/RR7/RR8 survived, RR3b + 2 mechanical fixes folded here). Pin: `db7fcd68`.

> **SEAM SHAPE (§2-§4) is SUPERSEDED by PART 4 OF THIS FILE.** (`DESIGN-v5-taxonomy.md` was a working
> title that never became a file at any commit on any ref; the work landed as `1.6.0-plane-abi-taxonomy.md`
> and was absorbed into Part 4.) Part 4 is the neutral primitive taxonomy
> (carrier axis / scope hierarchy / 2-tier egress / WorkItem reserved-shape / re-derived capability set)
> after a 5-protocol neutrality panel + 3 re-panels. The SPINE below (§0-§1 law/forcing, repr(C)+sized/
> append-only/major-airlock versioning, ~~HOT/COLD~~ (SUPERSEDED 2026-09-27 by THE DESIGN §11.1), §5 chain, §6 state, §7 migration, §8 gates, §11
> acceptance) STANDS. Design status: **RATIFIED** — 17 adversarial passes (r1-r3 spine: 9 breaks fixed,
> 0 spine breaks; 5-protocol neutrality panel; 3 re-panels all RATIFY after the duplex-in/CostHold-out/
> WorkItem-lock/server-rename corrections). Implementation is live.

## Locked decisions (owner-ratified 2026-08-22)
1. **repr(C) plugin ABI NOW** — full dynamic-load parity with the export/plane conformance witnesses
   (`crates/plugin-loader/src/tests/{export,plane}_conformance_tests.rs`), not an in-process trait.
   (As recorded this read "parity with token-auth"; that name has never been code — #2.)
2. **1.6.0 is the FINAL release — there is no "after."** The extraction lands INSIDE 1.6.0 and BLOCKS the
   cut. Must be as rock-solid as the rest of the release.
3. ~~**HOT/COLD split:** HOT plugins (mcp/a2a) use the POD-fast lane; COLD capability plugins
   (store/secret/auth/hook/export) KEEP the existing JSON lane, UNCHANGED — no rewrite of shipping code
   or the 4 external store repos. Same plug, different lane by heat. Does not violate the Law.~~
   **SUPERSEDED 2026-09-27 by THE DESIGN §11.1 and §11.8:** every kind speaks the memory ABI, and every
   first-party plugin, the external store repos included, is rewritten on it.
4. **Plane `.so` trust = identical to current plugins:** operator-configured; busbar signs its own; third
   parties may ship unsigned and the operator may allow them. Reuse `plugin-sign` + config toggle.
5. Coding is live (owner "go" given).

## 0. Law
Plugin behavior ⟂ linkage. Compiled-in vs plugins-folder = packaging only. Seam ALWAYS used. ONE code
path. Every plugin (store/secret/auth/hook/export AND mcp/a2a) speaks the same protocol;
`export_conformance_tests.rs` — one crate LINKED and `dlopen`ed, folds compared, RED arm kept — is the
proof (#2). (As recorded this read "token-auth is the proof"; that name has never been code, and the
AUTH kind holds no both-ways witness at any tag.) **`core/src/mcp/` and `core/src/a2a/` cease to exist.** Core names ZERO plane types. This
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
  (2026-09-27, THE DESIGN §11.3: bytes survive only as a pointer + length payload blob inside a field of
  a kind's memory ABI; there is no JSON lane.)
- **repr discipline:** every shared enum `#[repr(u8)]`.
- **Soundness:** every door and table entry is `extern "C"` (an escaping panic aborts, §11.11 M3); `free` never panics; opaque plane-state handle `Send+Sync`.
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
> **SUPERSEDED 2026-09-27 by THE DESIGN §5–§7 for the egress, subprocess, credential and metering rows of the
> table below:** a plane writes an unauthenticated request in answer to the kernel's ATTEMPT piece (§12
> below) ~~on a `ConnId` from `route.next`~~; the connector owns
> pinning, SPKI and mTLS; a subprocess is a carrier need; credentials are auth objects, never a host-minted
> header; `meter_charge` becomes the expected units of `arrive` plus the plane's unit reports; `auth_resolve`
> is gone. **SUPERSEDED 2026-09-28 by THE DESIGN §11.12 for the remaining rows:** the host services a plane
> calls are the `HostSlots` families. A plane's journal writes are `on_piece` record writes; a chained record
> kind keeps its declared framing (§5), now a per-record-kind declaration in the plane's tail, so deployed
> chains still verify. The kernel's own audit chain is the fixed record of THE DESIGN §1. DispatchScope stands.

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

> **THE BASELINE DOCUMENT DOES NOT EXIST AND NEVER DID — OWNER RULING OWED.** `ARCH-SYMMETRY-REVIEW.md`
> was cited here as the baseline. It appears in **no commit on any ref**: an object-path scan over the
> whole repository (`git rev-list --all --objects | grep -i arch-symmetry` → **rc=1**, 13,625 commits /
> 2,391 refs, plus both stashes and reflog-only commits) finds the name has never been in any tree.
> It was not deleted and it has not moved — `git log --all --diff-filter=D` is empty for it too.
> **What survives is the number and nothing behind it:** `4/10 (Seam B an 8, Seam A a 2)`, with no
> rubric, no dimension list and no evidence. A fresh reviewer with no prior context therefore cannot
> produce a score commensurable with the one they must beat, so **"≥9, up from 4" is UNPASSABLE as
> stated** — not vacuous: there is a target, but no comparable origin.
> **The salvage, which needs an owner ruling and is NOT taken unilaterally here:** the six bullets
> below are self-contained and objectively checkable without any baseline, and `GOAL-1.6.0-drive.md`
> already substituted them for the missing document (that file is `GetBusbar/busbarAI-private` →
> `goals/GOAL-1.6.0-drive.md:409`, not a path in this repo). Grade the CHECKLIST, or re-derive a baseline;
> do not grade a 4→9 delta whose 4 has no artifact.

Baseline (asserted inline, unsourced): 4/10 (Seam B an 8, Seam A a 2). To EARN ≥9, the rerun must find
the following resolved (the extraction resolves each by construction — this is the checklist):
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

> **THE BASELINE DOCUMENT DOES NOT EXIST AND NEVER DID — OWNER RULING OWED.** Same proof as §11a:
> `git rev-list --all --objects | grep -i core-engine-quality` → **rc=1**. Never committed, never
> deleted, not on disk anywhere, not in a sibling repo. The six dimension sub-scores below are the
> only trace of it that exists. Because this gate is a **HOLD** ("must not regress"), an absent
> baseline makes it **VACUOUS** rather than unpassable: no rerun can be shown to hold or regress
> against numbers no artifact supports, and `tests/benches SHOULD RISE 8→9` has no 8 to rise from.
> **What is NOT vacuous, and is what this gate should lean on:** the sub-bullets map onto gates that
> are machine-checkable with no score at all — the <1µs perf gate, the alloc gate, and the LLM
> byte-identity + freeze witness in §8 above. Those either pass or fail on their own evidence.

Baseline (asserted inline, unsourced): 9/10 (alloc 9, locking 9, algorithmic 9, memory 10,
cleanliness 7, tests/benches 8). The rerun must confirm:
- Hot-path alloc/lock/memory dimensions HELD (the <1µs + no-per-token-crossing gates protect them).
- The LLM money path byte-identical + freeze 0 (extraction didn't touch it).
- tests/benches SHOULD RISE 8→9: the perf gate + alloc gate add the criterion benches the audit flagged
  as missing; also fold the 1.5.1→1.5.4 perf-regression wins (pool_upstream_creds HashMap lookup,
  Candidate SignalBag widening, unconditional now()) for headroom.
- Net engine score ≥ 9 (regression below 9 fails the cut).

## 10. What this buys (the sell)
- **The claim becomes true, not aspirational**: mcp/a2a are plugins in the SAME sense as the export
  and plane fixtures that hold the tree's only both-ways witnesses (#2) —
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

## 12. The plane driver (owner-approved 2026-09-28)

The kernel serves every plane through ONE driver, in `busbar-kernel` (#36: the loop, the registry, the
teller, the sessions). It implements the teller loop's `Units` and `RouteAwait` over the one
dispatcher's plane handle, so `run_unit_async` and `open_unit` drive it and no second loop exists
(#26, #28). A compiled-in and a dropped-in plane reach it through the same table (THE DESIGN §11.4).

**Async completion.** The dispatcher answers the driver through an async completion (a waker on the
reply slot). The driver's control loop runs on the caller's runtime task and never blocks a runtime
thread; each crossing runs on the dispatcher's owning worker.

**One unit, step by step** (THE DESIGN §1's order):

| State | Plane op | Kernel |
|---|---|---|
| route | — | matches the request to its guest-list line (THE DESIGN §6) |
| authenticate | — | the line's auth verdict and identity (THE DESIGN §6) |
| size gate | — | size, rate, source and budget gates |
| decode | `arrive` (pure) | reads the op class, the principal need, the dialect and the expected units |
| verify → approve → admit | `project` (pure, once per unit, when a hook is bound) | scope seals the destinations; request-stage hooks see the projection; the budget admits (§7) and opens the hold |
| refused | `refusal` | audits the refusal and encodes it; nothing was charged |
| route | the `on_piece` pump | below |
| meter | — | the last cumulative units are final; only far-end-reported units bill (§7) |
| audit | — | the one fixed record (§1) |
| exit | — | one sealed line; a late line files under the arrival window (§7) |

**`project`.** A pure plane op that writes the hook kind's own `RequestView` (its plane-derived fields,
and a projected body where the plane has one — the `{tool, arguments}` projection of §9) into host
buffers. The kernel fills the stage fields (attempt number, candidates, previous failure, outcome,
status) from the route walk. 1.5.5's hook tests run verbatim against it (#85).

**The route pump.** The route step is the kernel's existing egress walk — pool, member pick, breaker,
allow-list, pin, failover and exhaustion terminals; the driver builds no second walk.
- The kernel KEEPS the caller's body and re-pushes it on every attempt. Each attempt starts with an
  ATTEMPT piece (`FROM_KERNEL`, carrying the member and the attempt number); the plane answers with
  the request bound for the far end: the verb and the target as explicit fields, then the dialect
  fields and the body. The transport calls the attempt binding's auth at its points and sends (THE DESIGN §6).
- Far-end pieces are pushed `FROM_FAR_END` with their status. The plane's answer may carry a verdict
  (ok, retry, hard) beside the walk's own status table. The walk fails over only before the first byte
  reaches the caller; a retry verdict after the first byte is treated as hard.
- One attempt is live per unit; there is no hedging.
- Backpressure is `emitted`/`more`: a full reply buffer answers `more = 1`, the kernel flushes, waits
  for the caller's side to be writable and calls again.
- Every answer carries cumulative units: they feed the budget check (which may use estimates) and the
  checkpoint cadence (§7); a checkpoint that dries the budget under `cut-stream` cuts the unit, the
  plane renders the error frame through `refusal`, and one Abort line settles (§7).
- Record writes in an answer go to the store's plane-record slots as coalesced write-behind batches.
  A record kind the plane declares as chained keeps its declared framing (§5: length-prefixed or
  pipe-separated, with or without the scope in the digest); the host frames and verifies its chain,
  and the boot-verify golden over deployed chains stands. This applies to plane record chains only:
  the kernel's own audit chain is the fixed record of THE DESIGN §1.

**Cancel** (client drop, deadline, reload). The driver keeps its own facts — whether the far end
answered, whether the reply streamed, the last reported units. On every path it controls (deadline,
cut, reload) the driver makes the ticketless `cancel` call itself before the loop future ends; a caller
that goes away drops the future, and then the ticket goes to the dispatcher's client-drop path, which
makes the cancel crossing on its worker. Nothing crosses the dispatcher inside a `Drop` (the loop's
`abandoned` path). The disposition bills by the four 1.5.5 cancel rules; a FAULT or absent disposition
bills as `CANCEL_FAILED` (nothing); the budget hold is released as its own act.

**Sessions** (a duplex carrier, Part 4 Axis 1). `open_unit` runs the steps to the door and admits at
open; pieces then flow both ways on the session's tickets. Unsolicited output reaches the kernel through
the plane instance's ONE driver ticket: the plane wakes it, its `drive` answer names the sessions with
output ready, and the driver calls `on_piece` (`FROM_KERNEL`, empty) for each. There is no per-session
driver ticket. Per-turn units are session-account checkpoints and the end writes one sealed line (§7).

**Inbound webhooks.** A plane's webhook routes belong to that plane plugin: its snapshot declares them
as public routes served by its `serve` op, and its own settings decide whether it answers; neither the
kernel nor core config has a webhook switch. The route's signature is verified by an auth plugin's
inbound verify under the style the route declares, so the plane never sees the signing secret; the
plane refuses a replay through a one-time record claim. The surface is new in 1.6.0 and is registered
as such.

**Nested units, work continuations and probes are units of their own.** A nested unit (`unit.nest`)
is a child of its caller. A work continuation is a NEW unit with its own arrival, admission and window;
its principal is the one its work handle recorded. A health probe is a kernel-originated unit pinned
to one member: a plane that declares probes answers an `arrive` for the probe claim and the ATTEMPT
piece with its probe request, the breaker service classifies the answer as it classifies organic
traffic, and the probe is zero-billed and draws no lease (§1's exempt origins).

**What the plane ABI v1 gains for this** (a v1 layout edit before the 1.6.0 tag, THE DESIGN §11.11 R9):
the `FROM_KERNEL` piece source; the ATTEMPT fields on `OnPieceIn` (member, attempt number); the
answer's verdict on `OnPieceOut`; the `project` op; the plane's `drive` in/out with a host buffer for
the ready sessions; a public flag on a snapshot route; the probe claim and the probe tail flag; a
per-record-kind chain framing declaration in the tail (verify framing for plane record chains only). Each
lands with its validator beside it and a RED test per rule.

**The driver's contract, as landed and ruled (K1, K2, K5, K6, K7, H3, FOLD-LLM2; ARCHITECT rulings
2026-09-28/30).**
- *Crossings.* The pure ops (`arrive`, `refusal`, `project`) cross ticketless on the caller's task; only
  ticketed ops run on the dispatcher's worker. The kernel mints a `unit` key and carries it on
  `arrive` and every `on_piece`; the caller's head (method, target, fields) is delivered ONCE, at
  `arrive`, and the plane keeps what it needs keyed by `unit`. After an answer with `more = 1` the
  driver re-calls `on_piece` with the same `from` and zero bytes; `more = 1` with nothing emitted, or
with `EMIT_DONE`, is FAULT, and a non-READY answer takes no early return past the unit and record
checks. `on_piece` carries the route's pool.
  Every piece also carries, lent from the arrival, the claim and dialect it arrived on (a plane with
several doors needs them) and the caller reference: an opaque per-principal value, HMAC-SHA256 under a
key HKDF-derived from the node's signing material (label `busbar caller-ref v1`), minted by the
identity crate — a plane never sees the raw principal. A plane that does not serve the method
declines with 405. The order at the door is route →
  authenticate → size gate → `arrive`, so 1.5.5's 401 comes before its 413.
- *Refusals.* A refusal's code crosses as an opaque plane-local `u32`; `refusal` receives the unit,
  the plane code and the retry-after, and — for a refusal with no unit — the TARGET, which the plane
  renders by its own path rule. Before `arrive` the router sets the refusal dialect from the route:
  each declared route carries an opaque `refusal_dialect`. `arrive` may answer a status (400-499, only
  with REFUSED), which the driver uses and audits; a plane tail may override statuses sparsely, per
  (dialect or any, reason) — exact, then any, then the driver's default. A hook veto carries the
  hook's own clamped status and text. The llm plane's statuses equal the 1.5.5 goldens (pinned before
  the llm flip); a new plane's equal current `predev`. The reason codes crossing the plane ABI are an
  explicit `repr(u32)`, append-only table in `abi/` with a pinned test and a RED; the kernel adds no
  new reason codes. The kernel refuses a reserved `upstream_credentials: passthrough` with the plane's
  own sentence, declared in its tail (`caller_credential_refusal`).
- *Hooks.* The hook stages run at the head of the route leg, after admission, in the hook order
  1.5.5 used for that plane (per attachment where 1.5.5 differed). `project` may return a rewrite,
  which the plane applies and re-projects; `PromptView` carries plane-flattened messages; the
  projection may carry the end user. A far end exposes its candidates and a constraint the hooks
  apply.
- *Duplex sessions (K6).* Two plane tickets per session (one per side) and the instance's ONE driver
  ticket; one `SessionCaller` shared with inbound listening and the stdio session; every turn leg is a
  route walk under the session's ONE admission, inside the destination set sealed at open; cleanup
  runs exactly once. Money per §7.
- *Nested units and work (H3).* `unit.nest` and `work.*` are host services over per-(label, ticket)
  unit frames; `work.open`'s target is a 128-bit reference; a child accrues 0 at admission and its
  reported units at exit (`$`, on the money chain); the work book is in memory, as the legacy one was.
- *Probes (K7).* A pure probe schedule, bound to the far end; a member's health follows the 1.5.5 lane
  health configuration.
- *The switch.* The production composition of the driver and the kernel's host services is in ONE
  place, the serve path; a fold adds only its door rows. A development-only cargo feature flips a
  plane onto the driver during its fold and is deleted when the fold completes; both paths are
  oracle-proven while it exists. The llm flip's gate is every hook test green on the driver — 184:
  the 70 of llm origin through `project`, the 114 of kernel, loader and ranking origin (ARCHITECT,
  2026-09-30).

*Proven by:* the plane conformance suite (compiled-in and dropped-in through one table); zero
plane→host calls per chunk; the hook parity tests verbatim; the oracle families of each plane as it is
flipped onto the driver; the money suites for every money step.

---

# PART 4 — THE PLANE ABI NEUTRAL TAXONOMY (v5)

> *Absorbed verbatim from `1.6.0-plane-abi-taxonomy.md`, which this document replaced and DELETED (`49ab4aca2`) — that name is history, not a path. MACHINE-READ: `xtask/src/gates/plane_abi_neutrality.rs` parses the first `banned set` line below as its mandate. Do not reword that line.*


Merges into DESIGN-LOCKED §2-§4 (the seam SHAPE). Spine unchanged: Law §0, forcing §1, repr(C)+
versioning (sized/append-only/major-airlock), HOT/COLD tiers (~~HOT/COLD~~ SUPERSEDED 2026-09-27 by THE DESIGN §11.1: memory ABI only), opaque state §6, migration §7, gates §8,
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
> **SUPERSEDED 2026-09-27 by THE DESIGN §5:** one `conn` host table for every kind; a need asks for a raw byte
> stream or a framed transport; pinning, SPKI, mTLS and pools are the connector's and dialing is the carrier's.
> The chokepoint stands: the kernel owns the allow-list, pin, breaker and meter valves.

| Tier | shape | governs | subsumes |
|---|---|---|---|
| HTTP-request | reqwest one-shot + resolve-then-pin + SPKI + mTLS + HTTP head | url/ip/spki | today's mcp/a2a http |
| governed raw-connection | host opens a pinned, SSRF-checked, metered BYTE channel; plane frames on top; duplex | address/allowlist | **subprocess (MCP stdio) AND raw sockets (DB-wire/tunnel/RTP)** — subprocess is NOT a separate capability |
Both are `egress_open(&EgressDesc{ kind: Http|RawConn|Subprocess, ... })`; kind is data, the governance
is one path. Removes the 4 subprocess capability slots as protocol-specific furniture.

**Every transport acks back to the sender (OWNER ruling 2026-09-30).** *A plugin that sends data must
see the response.* Every transport — not only http — acks each request back to the sending plugin
through ONE transport-neutral reply descriptor, `READ_REPLY`, appended to the host connection table
(`abi/host/conn`, an append, no version bump): `{kind ACK|HEAD|BODY|END, code u32, reason span,
field spans}` over the transport kind's fields. At least one terminal ack per request; an egress
refusal is an ack FAILURE carrying 1.5.5's refusal text; a missing ack is a conformance failure.
`send_and_ack()` is the generic SDK helper and `exchange()` its http form, whose response is
`{status, reason, fields, body}` — the reason phrase as sent on h1, empty on h2 (so 1.5.5's texts stay
byte-identical). The per-stream head slots are neutral, `HeadSlots{stream, method, target, authority,
reason}`: the accepted side fills method, target and authority, the dialled side the reason; a frame
piece's status field is `code`. The egress class (resolve, pin, the SSRF refusal, 1.5.5 texts) is the
connector's (HEAD-FIELDS and KIND-SHARE rulings, 2026-09-30).

**A plane-originated hop lands where the judge looked (ARCHITECT DEST-PIN 2026-10-01; predev's
anti-rebinding rule kept).** Two appends, no version bump, guarded by the layout golden:
- `abi/host/service`: `DestJudgeIn.into: ServiceBufs`. Under `DEST_RESOLVE`, an admitted judgement
  writes every address it judged there, one span each (key = the IP literal, value absent; the first
  is the one a dial pins). Same judge, same single resolution; nothing is written without
  `DEST_RESOLVE` or on a refusal.
- `abi/host/conn`: `EstablishIn.within: AbiStr`, the address set the dial must land on (IP literals
  joined by `WITHIN_SEPARATOR`). The connector holds the address its own judgement pins at dial time
  to that set at the connect, before any byte is written; outside it, the stream is REFUSED. That
  includes a framed need, whose connect is at `WRITE_REQUEST`'s end, so the request never leaves.
  An entry that is not an IP literal refuses the ESTABLISH; an empty `within` keeps the dial as it
  was.
The plane checks the judged set against its prior-reached set and hands the same set to ESTABLISH,
so the judge, the overlap check and the dial see one address set. The SDK's `Services::dest_judge`
answers the addresses (`Judged::within`), and `Connector::establish` (with `Exchange::landing_within`)
takes the set.

## Axis 4 — METERING, money-scalar (reserve/settle: the DEMOTION BELOW SHIPPED ANYWAY — read the box)
> **SUPERSEDED 2026-09-27 by THE DESIGN §7:** `meter_charge` and `cost_reserve`/`cost_settle` give way to
> `govern_admit(expected_units)` and the plane's unit reports riding the `on_piece` return. What follows is the
> record of the older shape.

`CostBreakdown` is already a neutral money scalar (tunnel foil: byte-metering fits via `top("Bytes",…)`),
and `Usage` is opaque-component (tokens|bytes|frames|queries) — that covers all 3 shipping planes:
A2A meters once per hop (`a2a/meter.rs`), MCP charges per discrete round (`mcp/method.rs::charge_round`),
LLM per-token path is untouched. So per-request `meter_charge` is the 1.6.0 implement-set.
> ### ⛔ THIS DEMOTION IS OUT OF DATE. reserve/settle SHIPPED. (measured 2026-09-22)
>
> Its premise is *"zero production callers among the 3 planes"* and its conclusion is *"a reserved shape,
> **not implemented wiring**"*. Both are now false, and nothing about that is a scheduling question:
>
> * **The slots are wired to a REAL host.** `cost_reserve`/`cost_settle` are declared at
>   `crates/busbar-plugin/src/hot/host.rs:722,724` and bound at
>   `crates/busbar-kernel/src/plane_host/vtable.rs:121-122` — `cost_reserve: Some(super::cost_host::cost_reserve)`
>   — over 224 lines of host-owned `CostHold` lease registry
>   (`crates/busbar-kernel/src/plane_host/cost_host.rs`), with the neutral-seam twin at
>   `crates/busbar-kernel/src/plane_host/mod.rs:594` sharing the SAME registry. It landed as "minor-19".
> * **The `unimplemented!()` pair at `hot/host.rs:1348`/`:1359` is NOT the host.** It is `mod stub`, the
>   compile-surface fixture that type-checks the signatures and is never dispatched. Mistaking it for the
>   host is the easy error here, and this correction was written after making it.
> * **There are four planes, not three.** #18 makes STREAMING the fourth plane of 1.6.0 and #45
>   (OWNER-LOCKED 2026-09-20) puts its first billable cut in this release. That plane is the production
>   caller: `HostMeteringPort` forwards to both legs (`crates/busbar-voice/src/runtime/metering.rs:350,389`),
>   bound as the production path by `build_runtime_hosted` and reached from the live mount.
>   Tracker K2 is `[x]`: *"real per-key metering lease wired"*.
>
> **So no work falls out of this — an AMENDMENT does.** This paragraph and
> the retired duplex-plane design doc’s decision **D2** (*"reserved but **not present** in
> `PlaneHostVtable`"*, *"do **not** ship the slots in 1.6.0"*) both describe a tree that no longer exists.
> A reviewer trusting either would read the streaming plane’s D2 lease as unridden scaffolding; it is the
> production money path.
>
> The words *"the future high-rate-carrier **minor bump**"* were also a DECISIONS #15 evasion — "minor
> bump" is `1.6.x` with the letters changed, and *"an EXTENSION POINT, **not 1.6.0**"* is "out of scope for
> 1.6.0" with the words changed. Found by the banned-word adjudication (2026-09-22).
>
> **Checkable, so this box cannot rot the way the paragraph under it did:**
> ```sh
> grep -n "cost_reserve: Some" crates/busbar-kernel/src/plane_host/vtable.rs   # -> :121
> wc -l crates/busbar-kernel/src/plane_host/cost_host.rs                       # -> 224
> ```
>
> The paragraph is kept, not deleted: its REPANEL reasoning is the record of why the slot was demoted, and
> that reasoning was correct on the day it was written.

**[SUPERSEDED BY THE BOX ABOVE] reserve/settle (`CostHold`) is DEMOTED to an EXTENSION POINT** (REPANEL-2 + REPANEL-3 both: zero
production callers among the 3 planes; its only justification was the *deferred* RTP carrier, so shipping
it trips acceptance gate §11a "no 0-caller ABI" and v5's own "implement only what the 3 planes use"
rule). The `CostHold` TYPE stays in place (fully tested) — **and the streaming plane is now its rider.**

## The re-derived CAPABILITY set (implement only what 3 planes use; rest = extension points)
NEUTRAL CORE (tunnel-proven, all/most planes): `govern_admit`, `meter_charge` + `cost_reserve/settle`,
`egress_open`(2-tier)/`poll`/`write`/`close`, `breaker_admit->AdmissionId`/`breaker_settle`,
`journal_append(scope,content_bytes,&FramingDesc)`/`journal_read`, `metrics_emit`, `clock_now`,
`auth_resolve`. Egress carries a credential-REF (host mints per-hop bearer / RFC8693; plane never holds
plaintext). NO `secret_resolve`. **SUPERSEDED 2026-09-27 by THE DESIGN §5–§7:** metering, `egress_*` and
`auth_resolve` give way to `govern_admit` + unit reports, the `conn` table and the auth object; the plane still
never holds plaintext.

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
> **SUPERSEDED 2026-09-27 for egress and metering by THE DESIGN §5–§7;** the carrier, scope and WorkItem items stand.

IMPLEMENT: carriers {request/response, response-stream, **duplex-session** (MCP stdio-serve rider)}; the
**WorkItem reserved-shape** (sized/versioned, kind-tagged inbound+emit, witnessed); scopes {dispatch,
session [riders: MCP stdio-serve + A2A relay], durable [rider: A2A tasks]}; egress {http, raw-connection
incl subprocess}; metering {**charge only**}; neutral core + trust-family + nested-dispatch (depth-bounded,
RR7) + work-handle.
NOT BUILT in 1.6.0 (the layout reserves the tag; building one is a future ABI version, never a 1.6.0 patch): subscription/pull + accept-loop carriers; ingress work-item settle (ack/nack/dead-letter);
ordered-processing lease; **metering reserve/settle (`CostHold`)**. The TAXONOMY + the WorkItem reserved
shape guarantee each is a clean add, never a break. That is "fits-or-cleanly-extends for the next 5."

---

# PART 5 — THE EXECUTION PLAN

> The ordered plan lives in ONE place: the TODO's **PATH TO DEV-GREEN** (P1–P6), then PERF, then
> DEV-GREEN again. The W0–W8 waves and the granular table that used to sit here were retired
> 2026-09-30 (superseded by the TODO phases); git keeps them. What stays here is the DEV-GREEN
> definition and the owner rulings that shape execution.

## DONE = DEV-GREEN (the definition every wave drives to)
DEV-GREEN is reached when ALL of the following hold and turnstile boards ADMIT:
1. **Oracle byte-identical vs the 1.5.5 golden on every family** (money sacred, #9/#10). The ONLY
   accepted diffs are the entries of `testing/shadow-oracle/accepted-differences.json`, all 45
   re-signed by the owner 2026-09-30. Everything else byte-green.
2. **All P-item behaviours match 1.5.5** — refusal-reason collapse, unary/empty terminality,
   wrong-provider attribution, voice tool-args — fixed as BUGS, not signed (#43/#71). Gemini usage
   is the exception: a registered, signed money improvement (item 1).
3. **The full xtask gate battery is GREEN** — construction, kind-isolation (7 kinds, dep-wall allowlist
   ⊆ {busbar-contract}, #40), plane-purity, naming (#34),
   no-codec-crate (#39), no-testkit (#33), kernel-string-neutrality (#49), transport-scheme fail-closed
   (#50), seal-witness (KernelSeal kernel-only/unforgeable, #65), Pass/Grant per-call binding (#74),
   admin↔config parity (#52), secret-hygiene blocking (#53), legacy-drain = 0 (#19/#37).
4. **Conformance MUST-set landed + green for all 5 planes** (llm/mcp/a2a/streaming/decisions), incl.
   landing `integration/conformance-b` (#68).
5. **Audit-ledger clean + the architecture audit, as the owner rules on QUESTIONS Q128** (#60; the §11a
   baseline the ≥9/10 score depended on never existed).
6. **turnstile BOARD = ADMIT → train ff `predev`→`dev` = DEV-GREEN** (#32/#67).

## money-touching step shadow-oracle-gated; each wave loops `/codeaudit` to 2 clean passes #60)

### W0 — Foundations (DONE / verify)
- Part 2's decision ledger perfect (conflict-audit to 2 clean passes).
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
Agents: delete `busbar-core`; land `busbar-core-{admin,oauth2,connector}` (substrate split, #37); drain fat substrate runtime
into the kernel-8; delete `busbar-voice` (voice = streaming dialect, #18). Gate: legacy-drain = 0.

### W5 — Folds: planes / contract / plugin-infra / config [#39/#38/#35/#33/#40/#47/#49/#51]
Agents (parallel, disjoint): (a) planes → 5 one-crate each, codecs/dialects fold IN; add the
`decisions` plane crate `busbar-plane-decisions` (jev dialect, #48). (b) `busbar-contract` = the ONE ABI
crate (fold contract-transport); `busbar-api` retires, money records → busbar-kernel-ledger
byte-identical (#38/#35). (c) plugin infra = `busbar-plugin-loader` over `busbar-contract` (the SDK lives in contract, #33), no testkit;
dep-wall allowlist gate (#40). (d) CONFIG reshape: per-plane sections (pools/tools/agents/decisions/
streams), `models` beside pools (the 1.5.5 shape), provider = connection + default protocol/error_map overridable
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
  `docs/ci/feature-sets.md`, `docs/{a2a,mcp}.md`, `docs/proof/README.md`)
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

## UNATTENDED SAFETY (owner away)
Blind-swarm ONLY additive/dormant/purely-local work the oracle can prove byte-identical. Any step that
SWAPS the shipped request path or touches the money book waits for a green candidate binary + serial
execution + is surfaced to the owner. Money is sacred; deny-and-fix on any user-visible byte; never
self-approve a billed-byte change. Quality + byte-identity outrank raw agent count.

## Owner rulings — 2026-09-23

Seven questions were put to the owner one at a time. The answers are below, with what each one
costs. Two of them turned out to be rulings against the CODE, not against this document: rows 33
and 66 were already right and the code had drifted away from them. That is the blueprint working
as intended — the drawing did not move, the building did.

| Q | Ruling | What it changes |
|---|---|---|
| 1 | Auth vocabulary (`bearer`, `spki`, `mtls`) is **protocol vocabulary, not an instance noun** — agreed. `sigv4` stays an instance noun. | The neutrality gate exempts the three; ~265 files stop being counted as leaks. |
| 2 | **Something must still run 1.5.5 and 1.6.0 and confirm they are the same.** | The parity bindings survive wherever they live. The doc collapse may not orphan them (item 21). |
| 3 | **Fix both security advisories in 1.6.0. Disclosure timing is the owner's, not the release's.** | Item 22 becomes code work; no disclosure gate blocks the cut. |
| 4 | **No currency.** *"it assumes you change $1.50 to 1.50GBP we convert? no, hence 1.50 is it."* | #66 stands UNAMENDED — see below; the code, not the row, was wrong. |
| 5 | Admin verb count — the question was asked badly and is re-put in plain English. | Open. |
| 6 | **Delete testkit.** Second time this has been ruled (see #33, ruled 2026-09-22). | `crates/busbar-kernel/src/testkit/` ceases to exist. |
| 7 | The list is reviewed with the owner before sign-off, then burned down at full pace. | Sequence: docs -> adversarial audit -> sign-off -> burn. |

### On #4: the ruling was right, for a reason that had not been found yet

The owner's stated reason was that currency is a display label. It is not — and that makes the
ruling MORE correct, not less. `CurrencyCode::minor_exponent()` returns 0 for JPY, 3 for BHD, 4
for CLF and 2 otherwise, and that number feeds `nanos_per_minor()`. It is the ROUNDING SCALE.

The defect this exposes: an admin `amend_rate_history` request body may carry `"currency": "JPY"`
(`crates/busbar/src/root/units_admin/mod.rs:1113`). That single three-letter string shifts
`nanos_per_minor` from 10,000,000 to 1,000,000,000 — **the same rate figures on a corrected card
become 100x different money**, with no conversion and no audit of the scale change. Every other
construction site in the repo is a hardcoded `CurrencyCode::USD`.

Measured against the published tag: `CurrencyCode` appears in **0** files at `v1.5.5` and
`amend_rate_history` does not exist there. Both are 1.6.0-only, so removing them restores parity.

**CORRECTION — the third measurement in this paragraph was a false zero and is withdrawn.** It
claimed the admin `openapi.json` carried 0 occurrences of `"currency"` at `v1.5.5`. The grep ran
against `crates/busbar-core-admin/src/v1/json/openapi.json`, a path that does not exist at that
tag — the crate was renamed. `git show v1.5.5:<missing-path>` produced nothing and `grep -c`
reported 0. No positive control was run. At the real path,
`crates/busbar/src/admin/v1/json/openapi.json`, `UsageView.currency` is present at `:2564` and is
listed as REQUIRED at `:2590`. It is a published 1.5.5 response field and it STAYS; deleting it
would have broken a shipped contract and moved the file away from the golden.

The two facts are consistent, and the distinction is the owner's own: the published field is a
DISPLAY LABEL on a read-time view — *"thats a display issue for user"* — while what #66 forbids is
a currency TYPE on the money path. The label survives; the type is gone. #66 and the 1.5.5 wire
contract do not conflict.

Ruled NAY under standing money authority. The scale becomes one constant.

### On #6: why testkit keeps coming back

It was already ruled on 2026-09-22 (*"delete it. wtf is a testkit."*) and #33 has said since
2026-09-18 that there is no testkit. It is still here: `crates/busbar-kernel/src/testkit/`, 7
files, 2,188 LOC, at `crates/busbar-kernel/src/lib.rs:320`. **CORRECTION:** an earlier reading
of this line claimed the module was not feature-gated and therefore shipped in the production
binary. That was wrong — line 319 carries `#[cfg(any(test, feature = "test-support"))]`, so it
never entered a production build. The error was reading the `pub mod` without reading the
attribute above it. The reason to delete it does not rest on that claim and is unchanged: 180
references across 60 files, only 5 of them inside busbar-kernel. Every outside consumer is a plane. The kernel ships test
scaffolding whose only users are plugins, which is the exact thing #33 forbids.

The crate-local testkits are NOT this and are KEPT: `busbar-a2a` (213 LOC), `busbar-mcp` (281),
`busbar-oauth2` (65), `busbar-llm` (44). A plugin testing itself is self-contained and correct —
the same principle as self-naming.

## Owner rulings — 2026-09-23, second set

| # | Ruling | Consequence |
|---|---|---|
| 8 | **The 1.5.5 under-billing is CORRECTED in 1.6.0, with no customer restatement.** | C4 wins over C3 on the 42 affected cells. |
| 9 | **Land the ABI rider. C2 is real, not amended down.** | §11a stands as written; the drop-in fold gets built. |
| 10 | **No date. The plan is for DONE.** Owner: *"forget a date, i want a plan for DONE"* and *"it takes what it takes."* | The list is ordered by dependency, not by what fits before a deadline. |

### On ruling 8 — why no restatement is the correct answer, not the convenient one

The register entry `G-1`, owner-signed 2026-09-07, records that published 1.5.5 **under**-counted
every grounded / server-tool turn on one dialect by exactly one term — 32 of 222 tokens, 14%.
`M-3`, `PR2-D4` and `D-3` are the same shape. 42 cells total, all marked `kind: "breaking"` by the
register itself.

The direction is what settles the disclosure question. Customers were charged LESS than the rate
card specified, not more. Nobody was overcharged, so there is no restatement owed to anyone — the
loss was busbar's, and it stops in 1.6.0. Had the sign been the other way this ruling would have to
be the opposite, and that asymmetry is the point: a bank auditor asks who is short, not whether the
number moved.

This is the first place C3 and C4 have been in open contradiction, and the contradiction was real
rather than a misreading: C3 demands 1.6.0 serve the same bytes 1.5.5 served, and those bytes are
wrong. **C4 outranks C3 where they meet.** The 42 cells become signed C3 exceptions carrying this
ruling as their reason, and `accepted-differences.json` grows a sign-off field to hold it (item 11).

### On ruling 9 — what "C2 is real" costs

`open_export` has zero callers anywhere in the tree. `open_plane` has zero production callers. The
shipped binary never mentions `load_plane` or `DynPlane`. All five real planes are built on the
native Rust `PlaneDecl` (`plane/registry.rs:811`), not the `#[repr(C)]` ABI one
(`busbar-plugin/src/hot/decl.rs:131`) — which is used by exactly one crate, the example.

So "every plugin compiles in OR drops in" is today true of zero kinds in production. The tracker's
H6 names the two honest outcomes — land the rider, or amend §11a — and says shipping while calling
it satisfied is not one of them. The owner has chosen the rider: the C-ABI-to-native decl adapter,
the loop routed through `PlaneHostVtable`, one real plane built as a `cdylib`, and `open_plane`
called from the composition root. Transport gets the same treatment under item 6.

## Anti-recurrence
- Every settled decision is a Part 2 row with an enforcing gate; drift → RED, not re-litigation.
- THIS FILE is authoritative — Parts 1, 3, 2, 5 in that order; all other docs reconciled to it or
  deleted (#14/#58). One canonical doc per topic, edited in place.
- READ-FIRST hook + this file re-read every turn; cite-or-ask, never guess.

# PART 6 — THE RELEASE ENGINE

Everything in Parts 1–5 describes the product. This Part describes the machine that ships it. It
lives in **two repos**, and that split is the single most common source of "I can't find the
autoscaler" confusion.

## The branch roster (#67) — four branches, and no others

| Branch | Rule | CI |
|---|---|---|
| `predev` | **permanent WIP.** Every in-flight session lands here and forks from here. | No push CI. predev MUST stay green: the LANDER's full proof runs before every push, and a train that would leave any gate or selftest red does not land. |
| `dev` | **release-train-write-only.** "Next version's WIP, nowhere near done." | full `ci.yml` |
| `qa` | promotion target. **The one release build happens here** — the PGO build that ships, tested for real. | full CI + the real-media matrix |
| `main` | **a push here cuts a release** — tag, GitHub Release, container promotion, `latest` moved. Irreversible. **`main` never compiles:** it tags and publishes the artifacts, by digest, that `qa` built and verified. | release orchestration |

**Never push `dev`, `qa` or `main` by hand.** `--force-with-lease` is permitted only on `predev`
(#61), which carries no protection rule and no ruleset. **Branch protection is on `qa` only** —
required CI and train-only pushes (OWNER ruling 2026-09-28); the ARCHITECT drafts the settings and
the owner applies them. Only the LANDER commits to `predev` and pushes it (`1.6.0-TODO.md`, THE RULES
2.6).

**The qa build is the bytes that ship** (owner, 2026-09-05): *"when qa is green it's prod ready and
we just tag it and move it to main and release, but the qa build is what we release"* and *"we
shouldn't be building again on main as that build is not technically what we QA'd."*

**The release shape** (the mechanism, live in `.github/workflows/release-stage.yml`): 1.6.0 ships as
`v1.6.0-rc.1`, then `v1.6.0`, from ONE staged record. `staged.json` names both: `rc_tag` mints the
git tag and the immutable image pin and nothing else; `tag` publishes, moves `latest` and fans out.
Nothing is rebuilt between them.

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

**The marketing site is observed, never depended on** (owner, 2026-09-06). Nothing in the release
path triggers, `needs:` or waits on the site deploy; the site keeps its own trigger. Site checks
run only after a release is public, and they can report but never gate.

## Where CI runs, and what it costs

CI runs on **Latchkey**, not EC2. The EC2 fleet is retired: it was costing ~$2k and is confirmed
fully torn down — zero instances, zero volumes, zero NAT gateways, zero elastic IPs. Latchkey is
both cheaper and the money oracle's home (**#56 wins over #29** — the oracle rides Latchkey, it does
not need a dedicated fleet box; `CI_RUNNER_ONDEMAND_FLOOR` is 0, not 2).

**Capacity order (OWNER 2026-09-28):** zero idle instances; Latchkey first; EC2 only as overflow,
under a launch cap and #78's spend breaker. The runner autoscaler runs as a scheduled Lambda
(`busbar-autoscaler`), choosing the cheapest spot region. Agent compute is Latchkey only, through one
shared job budget (`1.6.0-TODO.md`, THE RULES 6.1-6.3); the owner has ruled no extra build capacity
(2026-09-29). EC2 is allowed for the performance phase (§11.9).

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

   The `TURNSTILE_DISPATCH_TOKEN` secret exists (Q67, 2026-09-24). The workflow fails loudly and by
   name if it is ever absent.

## Deleting branches is free

No `on: delete` trigger, no `on: create`, no catch-all push glob — zero workflow runs and zero
job-minutes. (The comment at `ci.yml:23` claiming `branches: ['**']` is stale; the real trigger list
is narrow.) Deleting `pr/*` auto-closes those PRs, which also fires nothing, because `closed` is not
in the default `pull_request` types.


---

# PART 7 — CURRENT STATE

This document holds no status snapshot. The live state and the ordered path to DEV-GREEN are the
TODO's top section, **PATH TO DEV-GREEN** (`docs/design/1.6.0-TODO.md`). The earlier 2,579-line Part 7
snapshot was retired 2026-09-30; its load-bearing rules moved into Parts 0–6 (oracle scope and
per-release goldens → "Why the oracle"; the money-clock, admission-memo, pinned money proof and a2a
billed byte → §7; the export kind → §2; the LOC signal and duplicate rule → Definition of Done; the
positive-control rule → Law 8) and its live defects are TODO rows. Git history keeps the rest.

# APPENDIX A — THE MEMORY ABI IN DETAIL (the signed design, folded 2026-09-30)

The signed per-kind design behind §11 (reviewed in two adversarial rounds, owner-locked 2026-09-27).
§11 wins over this appendix where they differ; `busbar-contract/src/abi/` is the byte-level truth.
Cancel dispositions are the §11 set (UNKNOWN / NOT_APPLIED / APPLIED); the hook parity suite is the
184 v1.5.5 hook tests; `/metrics` and `/metrics/hooks` are listener needs of the prometheus export
plugin (§5), not core routes.

#### A. The shared mechanism (`busbar-contract/src/abi/mechanism/`)

##### A.1 The door

```c
const bb_door* busbar_plugin_door(void);   /* the ONLY exported symbol */
typedef struct {
  uint64_t magic;              /* DOOR_MAGIC "BUSBARPL", never "BUSPLANE" */
  uint32_t mechanism_version;  /* = MECHANISM_VERSION (v1.5.5 TRANSPORT_VERSION 1 -> 2) */
  uint32_t size;
  uint32_t kind;               /* 1 store 2 secret 3 auth 4 hook 5 export 6 plane 7 transport */
  uint32_t kind_abi;
  const bb_statement* statement;
  const void* ops;             /* 'static; begins with bb_ops_head */
} bb_door;
```

- **Crate shape.** The logic crate's only public item is `pub extern "C-unwind" fn door() -> *const bb_door`. The thin cdylib crate holds one line, `busbar_contract::export_plugin!(crate_x::door);`, which emits the `#[no_mangle]` forwarder.
- **Linked equals dropped.** A linked row holds the same `door` pointer and reaches the same `'static` table.
- **Retired.** The six cold symbols, `busbar_set_log_sink`, `busbar_plane_decl`, `busbar_transport_decl`, `busbar_plane_arm`, and the `.init_array` door registration.

##### A.2 The Statement

`bb_statement` is `repr(C)`, `'static`, append-only, and leads with `size`. It carries:
- name and version;
- `kind` and `kind_abi`;
- the marks bitset and exclusive-mark lists;
- rewrites;
- a settings-schema blob (JSON, off-path), `secret_fields`, `target_from`, `trust_from`;
- `owns` and `consumes` sections;
- needs (`direction`, scheme, `auth_style`, `target_from`, `trust_from`, `egress_class`, declared egress targets);
- `declares`: metric families (indexed), diagnostic ids, answers;
- `max_inflight`;
- offered auth points (transport);
- a kind tail.

The pack tool reads the canonical rendering from the `.busbar_statement` object section without loading the image, and the signed manifest carries that rendering plus `mechanism_version`. At admit, the loader compares the section, the door's Statement and the manifest. Any mismatch refuses the load and is a RED arm.

##### A.3 The call convention

```c
typedef struct { const uint8_t* ptr; size_t len; } bb_str;
typedef struct { const uint8_t* ptr; size_t len; uint32_t fmt; uint32_t flags; } bb_blob; /* fmt 0 absent 1 json 2 jsonl 3 octets; flags SECRET */
typedef struct {
  uint32_t size; uint32_t op; uint32_t flags;      /* RESUME */
  uint8_t deadline_class; uint8_t _r[3];           /* call|stream|connection|write_behind */
  bb_hostctx host; uint64_t ticket; uint64_t deadline_ns; uint64_t trace_id;
  bb_blob extensions;
} bb_in_head;
typedef struct {
  uint32_t size; uint8_t outcome; uint8_t _r[3];   /* host pre-fills from a const template: outcome=FAULT */
  uint64_t wake_at_ns; uint64_t lease;             /* lease: off-path lists and secrets only */
  bb_str error;
  const bb_metric_entry* metrics; size_t metrics_len;
  const bb_diag* diags; size_t diags_len;
  bb_blob extensions;
} bb_out_head;
enum { BB_READY, BB_PENDING, BB_FAILED, BB_REFUSED, BB_FAULT };
typedef uint8_t (*bb_op)(void* instance, const void* in, void* out);   /* extern "C-unwind" */
```

**Outcomes.** FAILED is distinct from any "no opinion" answer. FAULT is never read as a safe default. There is no UNSUPPORTED outcome: a null slot refuses the load.

**`bb_ops_head`, the same for every kind:**

| Slot | When | Notes |
|---|---|---|
| `validate` | validation | pure |
| `open(host tables, settings blob, secrets, gen)` | boot, control lane | may return not-ready |
| `refresh(gen)` | reload | may return not-ready |
| `retire(gen)` | after RCU drain | |
| `tick(now)` | kernel clock | returns the next tick time |
| `drive(driver)` | a driver ticket woke | §A.4.3 |
| `cancel(ticket, out bb_cancel_out)` | deadline, or client drop on request-path ops only | out carries a kind disposition |
| `release(lease)` | host done with off-path/secret bytes | |
| `close` | shutdown or retired instance | |

**Resume.** There is no `poll` slot. After a wake the host re-invokes the original op with `flags |= RESUME`, the same ticket, and the same `in`/`out`, which live in continuation-owned memory (§A.5).

**One dispatcher.** `Plugin<K>::call(op, in, out)` serves all seven kinds.

##### A.4 Not-ready and completion

1. **Tickets and admission.**
   - The slab is per (instance, worker), worker-local and free of atomics, with capacity `min(max_inflight, host_ceiling)`.
   - A request or stream mints one ticket and reuses it for all its ops.
   - When the slab is full, admission depends on the kind:

   | Case | Action |
   |---|---|
   | Hook gate | `on_error` |
   | Tap | drop, and increment `TAP_NOTIFICATIONS_DROPPED_TOTAL` (global cap 1024, host pool) |
   | Auth verify | queue up to the host bound, then 503; never 401 |
   | Request-path store (plane records) | kind failure |
   | Off-path store/export write | queue on the flusher, never drop; failure merges back |
   | Transport | exempt: per-connection token space |

2. **Conn ops never block.** On `NotReady` they register interest as `(conn, ticket or driver)`. The blocking `deadline` parameters at `host/conn.rs:170-174` are deleted, and `conn.wait` is interest registration only.
3. **Driver tickets.** A driver ticket is persistent and owned by the instance, and it does not count against `max_inflight`.
   - Conn readiness calls `drive`, and the plugin fans out to its call tickets through `wake`. This serves postgres `Connection`, valkey pipelining and h2.
   - `ConnStream` retires a connection whose op was cancelled mid-protocol.
   - The metric `bb_deadline_without_wake_total` must be 0 in every conformance script.
4. **`host.wake(hostctx, ticket)`.** It is `extern "C"`, callable from any thread, and never blocks. It pushes onto the owning worker's wake queue, the only atomic on the path. Transport's `WireWaker` folds into it.
5. **Deadlines by class.**

   | Class | Deadline | On expiry |
   |---|---|---|
   | `call` | per-call budget | `cancel`, then the kind's timeout outcome (hooks go to `on_error`) |
   | `stream` | configured idle/overall timeout | |
   | `connection` | carrier idle timeout | |
   | `write_behind` | long | never cancelled on client drop or reload; retried with the same `op_id` |

   Deadlines come from the kernel's coarse clock. Reload drains; it never cancels.
6. **Host services that may pend** (`govern_admit`, `route.next`/`settle`, `hook.call`, `approval_redeem`, `nested_dispatch`, `journal.*`, `auth.call`); a transport op that calls `auth.call` is a ticketed op:
   - They return `NOT_READY{handle = (ticket, seq)}`.
   - On resume the plugin re-issues the same `(ticket, seq)` and receives the stored result. The host never re-executes.
   - RED test: exactly one reservation and one hook call across a not-ready `on_piece`.
7. **SDK.** An `async fn` op's waker calls `wake`, and `ConnStream` implements `AsyncRead`/`AsyncWrite` over conn. No plugin thread exists and no host blocking thread exists, except under **Q-DISK**.

##### A.5 Lifetimes

| Memory | Lives in | Valid until |
|---|---|---|
| `in`/`out` of an op marked `may_pend` in its kind contract | the ticket slot, or request-owned refcounted buffers (body `Bytes`); **never the worker Scratch** | op end or `cancel` |
| `in`/`out` of a READY-only op | Scratch is allowed | op end |
| Request-path results | host-supplied out buffers (`order_buf`, `field_buf`, `reply_buf`) | as `out` |
| Generation-scoped plugin bytes | plugin | `retire(gen)` |
| Call-scoped bytes of off-path lists and secrets | plugin | `release(lease)`; `BB_BLOB_SECRET` is zeroised |
| Tap input | a host-owned pooled buffer, independent of the request | the tap ends |

Miri/ASan test: a not-ready op, then 100 other requests on the same worker, then the wake.

##### A.6 Extensions

Unchanged: absent on the request path unless a pending field exists, built at generation time, and unknown keys ignored.

##### A.7 Envelope

- **Per-op metrics** are `bb_metric_entry{family_idx u32, kind u8, value f64, label_vals *u32|bb_str, n}`. The family, help, unit and label keys are declared in the Statement and validated once at `open`; per call the check is a range check. Diagnostics use the same indexed scheme.
- **1.5.5 bounds** are applied in full: 64, 8, 200/64/16, the name rule, non-finite values dropped, and a malformed entry dropped whole.
- **Hook status and describe, and export status**, are off-path. They carry the **1.5.5 metrics array as a JSON blob**, parsed by the unchanged `parse_status_metrics`: histogram, quantiles, buckets 8x8, the `ci_low`/`ci_high` pair, label, viz, max, dynamic names. The `busbar_` drop, the `hook=` label, deduplication and sorting of labels, and the 10 s stale-while-revalidate cache are kept.
- **Deleted:** `counter_add` and `metrics_emit`. The process recorder is unreachable.

##### A.8 Workers, the control lane, allocation, containment

- **Request-path ops** return READY or PENDING in bounded CPU.
- **Crossing watchdog, every build.** Each worker stores a crossing-entry timestamp with a relaxed store, and a monitor thread scans them.
  - On a breach of the threshold, N times, the instance is quarantined: new calls get FAULT (hooks go to `on_error`), plus a diagnostic and `bb_plugin_quarantined_total`.
  - A debug build aborts with a report.
  - RED test in a release build: a fixture that sleeps 5 s in `decide` at 1k rps leaves other pools' p99 unaffected after the quarantine trips.
- **Control lane.** Ops run on a serial queue per instance over a small pool. Each has a deadline (configure keeps 5 s) and is watched by the same watchdog. On breach the reload fails and the instance is unresolvable.
- **Zero allocation on the READY path.** A counting-allocator witness is 0 for each request-path op. A not-ready continuation comes from a recycled pool.
- **Design-level checks:**
  - zero plane-to-host calls per chunk;
  - a crossing under 1 µs;
  - zero allocations on the READY path;
  - zero contended atomics per chunk;
  - zero lost wakes.
- **Statelessness.** `busbar-contract` has no `static`, `OnceLock`, `LazyLock` or `thread_local` outside tests. Services are reached only through the host tables handed at `open` (gate `contract-stateless`).
- **Plugin closures.** The only busbar crate allowed is `busbar-contract`. Denied: tokio `rt`/`time`/`net`, the hyper-util executors, `tracing-subscriber`, the `metrics` recorder, `set_var` (gate `plugin-closure-deps`).

##### A.9 Versions (§10 ruling and §11.2)

| Constant | Value | Notes |
|---|---|---|
| `MECHANISM_VERSION` (was `TRANSPORT_VERSION`) | 2 | |
| store `ABI_VERSION` | 3 | |
| `SECRET_ABI_VERSION` | 2 | |
| `AUTH_ABI_VERSION` | 3 | |
| `HOOK_ABI_VERSION` | 2 | |
| `EXPORT_ABI_VERSION` | 3 | |
| `PLANE_ABI_VERSION` | 1 | new |
| `TRANSPORT_KIND_ABI_VERSION` | 1 | new |
| `ABI_MAJOR`, `ABI_MINOR`, `POD_VERSION`, `TRANSPORT_DECL_MAJOR` | retired | never shipped in 1.5.5 |

The loader checks in this order:
1. The manifest `mechanism_version`, before dlopen.
2. The `busbar_plugin_door` symbol exists.
3. `magic`, `mechanism_version == host`, and `kind_abi == host` for that kind. Older is refused with "rebuild against the 1.6.0 SDK". Newer is refused.

**Growth rule.** Op tables are frozen per `kind_abi`, and a new op bumps the version. Data structs grow by append under `honoured_size`. The host zeroes `out`, and the plugin writes back its own `sizeof`.


#### B. Per kind (`abi/<kind>/`)

**P** = on the request path; **O** = off-path.

##### B.1 store (v3)

- **Record blobs** are the tree's unit-map shapes plus the #81 scale discriminator. Rows written by 1.5.5 are read as whole units.
- **Fixed fields:** ids, cursors, windows, counts.
- **Slots:**
  - the full 1.5.5 op set (as in the first draft);
  - plane records;
  - the ten 1.6.0 ledger ops: `append_batch`, `reserve`, `slice_release`, `heads`, `session_put`, `session_remove`, `sessions_for`, `record_put`, `record_get`, `record_scan`, with the semantics in `store_adapter.rs` documented per slot (constant slice epoch, replay cache `REPLAY_TTL_SECS` surviving a restore, shipping ack);
  - batch slots `add_usage_batch`, `add_metering_batch`, `append_audit_batch`.
- **Writes.** Every additive or appending write carries `op_id` and is deduped, and uses the `write_behind` class.
- **Kernel side.** The migration read (`legacy_audit_head`, `legacy_cells_read`) and the marker run in the kernel over `StoreClient`; the `store-persist` cell proves them. ITEM-580 closes: the store's own declared version is read.
- **Tail:** `ephemeral`, `durable_plane`, `fork_refusal` (Q79).
- **Behaviour:** network stores use driver tickets; memory is always READY. There are no UNSUPPORTED fallbacks and no floor.

##### B.2 secret (v2)

- `resolve(settings blob)` returns a `BB_BLOB_SECRET` lease, or FAILED plus `error_kind` with no material in the text.
- `tick` renews vault leases.
- `{env: X}` and `{file: Y}` are Statement rewrites.

##### B.3 auth (v3)

**Tail:** `caps INBOUND|LOGIN|OUTBOUND`, `styles[]` with a per-style ~~`needs_body_hash` fact~~ auth-point set (SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists"), `cacheable`, aliases.

- **`verify` (P).**
  - In: ~~the credential and the named carrier fields~~ the neutral request at the style's auth points; the auth names its credential lines and the transport strips them (SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists").
  - Out: verdict IDENTITY, REJECT or PASS; identity `{subject, key_id, key_name, user, groups, provider, name, ttl_secs}`; a claims blob the kernel never reads on the request path.
  - ~~**The kernel keeps the inbound `CredentialCache`** (Q-INCACHE):~~
    - ~~consulted only for a `cacheable` plugin;~~
    - ~~Identify TTL clamped to 3600, default 300;~~
    - ~~Pass cached for 5 s plus jitter, and only when the chain later identifies;~~
    - ~~Reject never cached;~~
    - ~~4096 entries, keyed by provider instance;~~
    - ~~flush generation, with `POST /admin/auth/cache/flush` unchanged.~~
    SUPERSEDED by §11.11 R3; the auth plugin caches, and the flush count rides `refresh`'s envelope.
  - The name check at `auth/mod.rs:978` is deleted.
- **Login ops (O, off-path not-ready through its own need).**
  - `begin_login{redirect_uri, state, nonce, code_challenge, scopes}` returns the authorize URL or the form.
  - `complete_login{code, state, redirect_uri, code_verifier, submitted}` returns the identity.
  - The token exchange runs over the plugin's own need to its need-declared targets (§6.7).
- **Outbound (§6):**
  - `open(style, credential)` gives a handle, refreshed every generation.
  - ~~**The per-attempt `fields` call is made by the kernel before encode.**~~
    - ~~In: `handle`, `method`, `authority`, `canonical_path`, `query`, `timestamp`, `body_hash[32]` (only when the style declares `needs_body_hash`), `caller_credential?` (secret blob), `mode` Own|Passthrough.~~ SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists": the binding's transport calls the auth at the style's points (§6); `Head` gives method, target, authority and field lines; `HeadBody` adds the body; `caller_credential?` and `mode` are unchanged.
    - Out: fields written into `field_buf`, in order.
  - READY with zero fields means no header, so the upstream answers 401. That covers pre-mint and un-encodable keys (1.5.5).
  - The `ready` fact is read by the health prober.
  - Expired with a failed refresh follows §6.5 (Q-EXPIRED).
  - Anthropic classification, `anthropic-version`, `x-api-key` trimming, `api-key` and `x-goog-api-key` are byte-for-byte.
- ~~**Framer fact** `signs_nothing_after_auth`~~ a rule for every transport: nothing is added to the head after the auth has run (SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists"); with a RED test.
- **Inbound SigV4** moves into an auth plugin's `verify` over a store-read host service, keeping the dummy-secret timing equivalence for an unknown AccessKeyId.

##### B.4 hook (v2)

**Tail:** hook words; `kind_class` gate, rw or tap; grant intent (`prompt no|ro|rw`, `user`, `signals`); `infallible`.

**Views** (fixed, no JSON; a presence bitmask marks optional fields):
- the request view (the draft's fields);
- the static half of `candidates[]`, built at generation, with the dynamic fields filled per request;
- the prompt view and the **body blob, both present iff prompt ∈ {ro, rw}, identical for both**;
- the user view iff granted;
- the requested signals.

**Slots:**

| Slot | Contract |
|---|---|
| `decide` (P, may_pend) | Out: verb bits, `reject_status` + HAS, `reject_message`, `restrict_tags`, `order` into the host `order_buf` of `u32`. |
| `transform` (P) | Out: verb bits plus rewrite blobs. **The kernel reads only the bits; the plane parses and validates the blobs**, and proceeds unmodified on failure. A `ro` rewrite is dropped by the kernel from the grant. |
| `notify` (P, taps) | In is copied into the host-owned tap pool (global cap 1024, drop metric, stage projection with no prompt or signals, `groups:` filter). It never holds the request. |
| `configure`, `status`, `describe` (O) | Run on a **fresh management instance** through the same door. Status and describe return 1.5.5 blobs. Configure: ack equal to the pushed version, 5 s deadline, a nack does not commit. |
| routes, `serve` (O) | Routes are instance facts. Confined to `/hooks/<name>/*`; none/key/admin auth is enforced before `serve`; admin routes are admin-listener only. |

**Kernel normalizers, input type changed only:**
- reject > restrict (fail-closed, `on_empty`) > abstain > order through `from_ranked`;
- status clamped to 400–499, else 403;
- the full 1.5.5 sanitiser (control characters, U+2028/2029, U+200B–200F, U+202A–202E, U+2066–2069, U+FEFF, whitespace-only falls back to the default), capped at 300 characters on a character boundary;
- restrict tags trimmed, empties dropped;
- all enforced **host-side** on the fixed struct.

**`on_error`:** FAILED, FAULT, timeout and REFUSED feed the chain; `timeout_ms` 0 means the default.

**`infallible` hooks:** chain terminal `Weighted`, grants forced off, `on_empty` Reject, default timeout. Plain `weighted` stays zero-cost with no policy object.

**Boot:** `preopen_gate_hooks` aborts on a broken gate and never on a broken tap. Hook secrets are pre-resolved and fail closed.

**SDK helpers:**
- `lower_1_5_5_reply`: a typed-field mismatch returns FAILED, and an out-of-range index is dropped.
- `projection_json` matches 1.5.5 byte-for-byte: no `requested_model`, `tool_count` or `system_chars`; the `SignalBag` flattened in insertion order.

**Acceptance:** 184 v1.5.5 hook tests ported verbatim, plus memory-form RED tests for each malformed class.

##### B.5 export (v3)

- **Tail:** `streams[]`, pinned to the `ExportStream::ALL` order.
- **Slots:**
  - `deliver{stream u8, batch jsonl}`, built at batch time with the `fields:` projection applied kernel-side;
  - `scrape(families)` over the host snapshot service;
  - `status` (1.5.5 blob), `check`, `serve`.
- **Listener.** `/metrics` is served on the **data listener** through the export route exception, with confinement to `/metrics` or `/exports/<name>/*`, the reserved paths and the 64-header cap. `/metrics/hooks` stays a core route.
- **Behaviour.** Webhook and otlp use driver tickets. The `Host` and `Started` variants are retired.

##### B.6 plane (v1)

- **Tail** as in the first draft: sections, dialects, claims, per dialect: (route, transport, inbound default style, `refusal_dialect`), ingress, `route_cost`, `dialect_auth` (the outbound default only), admin routes, OpenAPI blob, `cli_help`, `dispatch_shape`, `billable_classes` indexed. `DISPATCH_BLOCKS` is deleted.
- **Settings.** Blobs to `open`, `validate_section` and `refresh` have `rate_card` and `fees` stripped kernel-side, with a RED test.
- **Slots:**

  | Slot | Contract |
  |---|---|
  | `arrive` (P) | Returns `op_class`, `principal_need`, `dialect_id`, `expected_units` (`bb_units`). |
  | `on_piece` (P, may_pend) | Writes into the host `reply_buf`. Out: `emitted`, `more` (backpressure: the kernel flushes, waits for the socket to be writable, and re-invokes); **cumulative `bb_units[]`**; destination facts (record writes); envelope. Zero host calls per chunk. |
  | `cancel` | Out disposition `ok_partial`, `failed` or `aborted`. The kernel bills the last cumulative units unless failed, and releases the budget hold (1.5.5 `FirstByteBody::drop` parity; oracle cell). |
  | `refusal` | Keeps the `GateRejected` marker. |
  | `serve`, `tick`, `hydrate`, `start` | as in the first draft |

- **Host services** use completion handles (§A.4.6). Deleted: `egress_*`, `pipe_*`, `cost_*`, `auth_resolve`, `metrics_emit`, `counter_add`, `verify_*`, `trust_evaluate`, `guard_url`, and the 58 stubs.
- **Rust tables** dissolve as in the first draft's table. `root/plane_decision.rs` moves into the existing `busbar-plane-decision`.
- **Plane crate fold (new).**
  - `busbar-llm`, `busbar-mcp`, `busbar-a2a` and `busbar-voice` merge into `busbar-plane-{llm, mcp, a2a, streaming}`, contract-only. Each kernel use becomes a host-table call or plane-neutral kernel code under C1.
  - The kernel features `plane-*`, `hooks-ranking` and `auth-admin-tokens`, and their 37 cfg sites, are deleted.

##### B.7 transport (kind v1)

- **Tables.** `CarrierSlots` and `FramerSlots` are re-headed with the per-connection token space; ~~there is no framer auth service~~ the framer calls its bound auth through the host auth handle (SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists").
- **Status by crate:**
  - tcp, stdio and ws are re-headed.
  - **http is a sans-IO h1/h2/grpc framer rewrite**, with no tokio or hyper runtime. It is the largest transport item.
- **Tail:** the auth points offered (THE DESIGN §6, "Auth points and guest lists").


#### C. Compiled-in uses the same table

##### C.1 Types and gates

**Types.**
- `admit(door: DoorFn, origin) -> Plugin<K>`, with a sealed constructor.
- `LinkedRow{door}` only.
- `Plugin<K>` is `!Clone`.
- `StoreClient`, `SecretClient` and so on live in the loader. Kernel traits leave `busbar-contract`, so a plugin cannot implement them.

**Gates:**

| Gate | Checks |
|---|---|
| `door-only` | Scope: every row in `linked_gen.rs` plus fleet `plugins.yaml`. rustdoc `--document-hidden-items` public items plus exported macros equal `{door}`. `linked_gen.rs` names only `<crate>::door`. |
| `origin-blind` | `Origin` is read only by sign/trust and `--list-plugins`. |
| `one-memory-abi` | The only symbol exported is `busbar_plugin_door`. No `busbar_call` or `ColdEntry`. No `serde_json` at kernel request-path dispatch sites. No `spawn_blocking` in the loader or dispatcher. The `rate_card`/`fees` strip is RED-tested. |
| `abi-location` | §11.5: no C-layout struct, ABI fn-pointer type or version constant defined outside `abi/`. |
| `contract-stateless` | §A.8 |
| `plugin-closure-deps` | §A.8 |
| `c1-literals` | All seven kinds, over kernel and loader. |

The `trybuild` case is replaced by a fixture root naming `<crate>::Anything` (RED).

##### C.2 Bypass fixes

| Bypass | Fix |
|---|---|
| store, hook, secret, auth, transport, plane, export | As in the first draft, plus the corrections above. The transport production path is the door, and http is rewritten. |
| `ProviderAuth` closed enum (`config/providers.rs:281-296`) and kernel minting | Style is an open string resolved against auth `styles[]`. Minting moves to `busbar-auth-outbound`. |
| Inbound SigV4 in the kernel (`auth/mod.rs:2071`) | Moves to an auth plugin's `verify`. |
| `PROTO_*`, `DEFAULT_PROTOCOL`, `STRATEGY_*`, `EXPORT_MODULE_PROMETHEUS`, `auth/mod.rs:46` | Become Statement data. The `--validate` text change is registered. |
| Contract statics (`codec.rs`, `records.rs:94`, `ids.rs:330`) | Deleted, with host tables used instead. |

##### C.3 Both-ways proof

The suite lives in `crates/busbar/tests/both_ways/<kind>.rs`, plus each plugin repo's `conformance.rs`.

1. **Linked leg:** the shipped `LINKED_ROWS`.
2. **Dropped leg:** the pinned cdylib through the real stage and verify path, **in a process with no runtime entered**.
3. **Same script:** a forced not-ready, then wake, then resume; a cancel; a release; driver tickets.
4. **Byte comparison:** the Statement, every out struct, the envelopes, and the `/metrics` exposition.
5. **Crossing counters in the SDK slot shims:** shim entries equal dispatcher crossings equal script ops, on both legs.
6. **RED arms:** those of the first draft, plus a manifest missing `mechanism_version`, a dev-era cold v3 artifact, a static in the contract, and a forbidden closure dependency.
7. **Kernel side:** teller-loop crossing counters above 0 for all seven kinds.
8. **Deleted:** the tests that compare the Rust API against the JSON ABI.


#### D. The SDK (`abi/sdk/`)

The dependencies are the ones in the first draft. The SDK provides:
- `export_plugin!` and the door macro: `catch_unwind` to FAULT, head and size checks, the ticket and lease slabs, resume dispatch, and panic-safe out writes;
- async and sync traits with no default bodies;
- typed views;
- `ConnStream` with retire-on-cancel, and `exchange`;
- `auth::{CachedHeader, RefreshingToken}`; the inbound credential cache is the auth plugin's own internal cache (§11.11 R3), and the SDK ships no cache helper;
- `hook::{projection_json, lower_1_5_5_reply}`;
- `Report` over family indices.

The header is `busbar_plugin.h`, generated and golden-checked.

**The #84 witnesses** are the C `busbar-secret-zerodep` and the Rust `busbar-hook-zerodep` (which exercises not-ready). Append-compat is a data-struct-only witness at the same `kind_abi`. A plugin at `kind_abi ± 1` is RED.



# APPENDIX B — DATED RULING LOG (owner and architect, 2026-09-24 → 2026-09-30)

Every binding ruling that was recorded outside this document, folded in verbatim 2026-09-30 so the
repo holds them. Later entries win over earlier ones; Parts 0–6 and THE DESIGN win over this log.
Operational chatter (launch orders, residue routing, session notes) was not folded.

### OWNER RULINGS 2026-09-24 (asked by the architect at the owner's request)
- Q10a: approve ALL config-schema drift (SecretRef bare `none`, rate_card.units, per-plane rate_card) — bless snapshot once card47 landed.
- Q18/Q22: land the InstalledLimits guard (kernel + core-admin halves, with test); snapshot + REVERT the openapi scheme/400 change.
- Q31: failed upstream generations surface as ERRORS (breaker fault) and CHARGE what the upstream reports it used.
- Q19: approve a signed accepted-difference for billing|rate-card|history-mid-window citing #79 (only that cell).
- Q21b: switch voice onto the streaming plane's units (priced at read, #71); delete the lease; kernel budget enforcement governs.
- per-plane fees (#47): IMPLEMENT — billable requests counted per plane so each plane's `fees` applies.
- Q29: KEEP the #42 rerank refusal AND refuse at BOOT when a served rerank model's card does not price search_units.
- Q25b: usage reads over an unpriced class answer a NAMED 409 (`unpriced_class`, body names model + class).
- Q14: DATE EVERYTHING (#79) — budget ledger stores arrival instant; /usage, enforcement, /metrics price at the card in force.
- Q11: approve re-pinning 376/381 needle repairs at their TRUE counts (then downward only).
- Q12 + Q25c: strike the unconstructed rows for 421 (+KNOWN_UNSHIPPED id, un-park 421) and money-one-function-view.
- Q8: push busbar-release branch fix/oracle-recorder-residual-gaps (not main) and move oracle-rust.pin ab88903→57da1eb.
- 388 residue ruling (architect): plane hydrate/start cross on the caller thread (HostCtx generation is per-thread; start calls clock_now) — documented exemption; build/config_validate run on the plugin worker.

### OWNER RULINGS 2026-09-24 (second batch)
- §13 / Q30c: a billed A2A byte = payload bytes relayed BOTH ways per hop (request + response), class `bytes`, priced by agents.rate_card; no card → 0.
- Q33c: KEEP the 400 for a wrong-typed stream_options (W2.28, 822d3f2b0).
- Q33d: STRIKE unconstructed row plugin-abi-keyed-units (+KNOWN_UNSHIPPED id).
- Q22c: RE-LAND the MCP sampling input bounds (from the pre-session snapshot) as configurable, named refusals with tests. Q22b: upstream_credentials stays REVERTED — per-server opt-in only (token-passthrough risk). MCP is new in 1.6.0: no parity constraint.
- Q29 boot (GENERIC, replaces any dialect-specific rule): a rate card lives at the PLANE SECTION level (the verb level: pools/tools/agents/streams/decisions). Every plane declares its billable unit classes; when a plane has a card, the kernel asks the plane for its declared classes at boot and REFUSES the config if the card leaves any declared class unconfigured, naming every missing class in the error. Explicit 0 counts as configured. Identical for every plane; nothing dialect- or model-specific. Per-model gaps stay a request-time #42 refusal.

### OWNER RULINGS 2026-09-24 (third batch)
- Q1: CARRY the three Vertex vendor fields (usageMetadata.trafficType, createTime, groundingChunks[].web.domain) in the codec IR so they round-trip — not gaps.
- Q3: reword accepted-differences rationale internal references (neutral prose, meaning unchanged) — covers entries at :61, :292, :415.
- Q5: move verify-deploy's getbusbar.com checks to a self-hosted runner whose IP Cloudflare trusts. (Owner asked what we push to getbusbar.com: NOTHING from this repo — verify-deploy only READS the live site after a release; releases come only from main, which this run never pushes.)
- Q9: owner: "money is a view on ledger x rate card" → durable-book postings must store COUNTS (+ card epoch), not money; reserved/settled/overdraft become read-time derivations via Tally. Architect executes after W2.4 releases root/.
- Q21a (owner): voice session ceiling = OPTIONAL setting in the streaming plane's own config; no default, no code constant; absent = no limit; plane enforces + settles on close. (Handed to P2-voice.)
- Q31 follow-up (owner): same-protocol non-stream passthrough of a failed generation RECORDS the breaker fault (read only the stop-reason field; body relayed unchanged; usage charged). (Handed to P2-failsig.)
- Q10b: covered by Q10a "approve all schema drift" — add busbar-plane-decision/src/config.rs to config-schema sources() at the Phase 2 close bless.

### 2026-09-25 ARCHITECT — THE KEYSTONE (composition root + test seams name no plugin). Cites Part 2 #2 rule (1) "compiled-in OR dropped-in, same contract, same loading path", #40, #49, spec §SEQUENCING TRAP (BUSBAR-1.6.0.md:1700-1731), owner Q1 (bearer/spki/mtls are protocol vocabulary, NOT instance nouns — overrides my earlier drain push on those three; renames already made stand, frozen rows for them are moot).
- K0 PlaneDecl dissolves: plain-DATA `busbar_contract::plane::PlaneDeclaration` (revive ae0622694 shape, +~192 LOC), fn-pointer table stays kernel-side and is BUILT by the kernel from the plane's contract declaration + `impl Plane`. No plane crate exports a busbar-kernel type. Prereq of F12/F13 and of K1.
- K1 linked-plugin table: a compiled-in plugin is registered through the SAME entry its cdylib exports. crates/busbar/Cargo.toml `[package.metadata.busbar.linked]` maps feature -> crate; build.rs emits $OUT_DIR/linked.rs (`extern crate X as _;` + `static LINKED: &[LinkedEntry]` of each crate's entry const); main.rs include!s it and hands it to the one registry path plugin-loader also feeds from dlopen. register_planes/register_protocols/register_diagnostics/register_ws_arrivals/units_mcp::seal/root::plane_decision all collapse into per-plugin entries. main.rs names no plugin crate. Every kind uses the same table.
- K2 units_* modules (root/units_{llm,mcp,a2a,voice}.rs + tests, root/plane_decision.rs) move into their plane family crate and register via that crate's entry.
- K3 cross-plane tests (need >=2 real planes: sampling_satisfy, core-admin error witness, capability_equality ...) are black-box: boot the built binary / the linked table and drive it by CONFIG (section verbs + provider protocol values are config data). They name no plugin crate identifier. Test-seam installers (install_test_seams, drive_*_verb_errors) register into a kernel test_support registry filled by each plane's testkit; readers loop the registry (SEAM-T).
- S11 residue: the lifted top-level keys (LIFTED_TOP_LEVEL_KEYS: mcp/tools/agents/streams/decisions) are DECLARED by each plane (its declaration's owned_config_sections), never spelled in the kernel (#49). `mcp:` key stays (customer-visible, CHANGELOG-documented 1.6.0 surface). DeployCfg field -> `endpoint` (serde skip, no wire change). Snapshot --write authorized ONLY for the McpEndpointSection type-label rename; diff must show nothing else.
- S04's tests/operation_names_cross_plane.rs literal ["llm","mcp","a2a"]: derive from the registered roster, not literals.
- K3 intake list (tests that name planes outside their family, created/kept by the C1 wave): crates/busbar-kernel/tests/residual_envelope_cross_plane.rs (S03 — the residual-dialect table is an llm-plane subject: pure move to busbar-llm/tests; the unmounted-plane test goes config-driven), crates/busbar-kernel/tests/operation_names_cross_plane.rs (S04, fixing its literal now), crates/busbar-kernel/tests/config_cross_plane.rs, plane_dispatch_cross_plane.rs, busbar-mcp sampling_satisfy_tests.rs (N05), busbar-llm hook_non_chat_projection_tests::subscribe_body_projects_its_target (N06 -> busbar-mcp), crates/busbar/src/root/tests/* + crates/busbar/tests/* (N01's 22 files).
- 2026-09-25 ARCHITECT (kickoff §4.5 correction): stream B (W4.x) runs only AFTER Phase 4 stream A is done — my earlier "W4.x when directory free" line and the plan's "P68-0 after W4.3/6/14/15" contradict §4.5 and are struck. P68-0 runs now in stream A; W4.3/6/14/15 run in stream B after. Order for the llm plane per dep-wall §6.6: P68-0 (contract shapes) ∥ P59-0, but P59-0 must not turn any currently-green gate red — if moving the codec's shared machinery (ir/, proto_codec, proto_stream, usage_*, wire_shim, …) into busbar-plane-llm reds a green gate, P59-0 stops after measuring and reports the exact edges, and the substrate drain slot (SUB-DRAIN) is defined from that measurement before the move lands.
- 2026-09-25 ARCHITECT (S10 residue): the kernel's own test binary never names a plane crate — "a plugin tests itself; the kernel never tests or names a plugin" (instance_noun_neutrality.rs header). registry_builtins' busbar_llm::DECLS / busbar_mcp::PROTO_DECL are replaced by NEUTRAL SYNTHETIC protocol declarations built in kernel test_support (a new file, e.g. test_support/neutral_protocols.rs): N protocols with neutral names, each with a trivial passthrough codec and the verb/ingress shape the 101 dependent tests exercise. Tests asserting real-dialect bytes are not kernel tests — they move to the owning plane crate. S02's positional reads keep working because the synthetic set is fixed-order.
- D1 follow-ups: plugin repos' pack build = cargo build --release -p busbar-plugin-loader --features pack --bin busbar-plugin-pack (post-promotion re-pin task); sweep/file-verdicts must re-path crates/plugin-sdk/src/pack.rs -> crates/plugin-loader/src/pack.rs (+tests) — L1 ledger pass.
- K3 intake +: crates/busbar/tests/ws_composed_battery.rs (D3a composed transport cells; composition-root naming transports) and kind-isolation:matrix vocabulary RAISED rows for transport-grpc/tls/ws -> L5.
- 2026-09-25 ARCHITECT: P59-0 not landed (3 green->red rows, p59-0-gatediff.md). The llm dialect move waits on the #83a substrate-values split (spec roster SPLIT row + #83(d)); SD-0 measures per-item destinations, then SD-1..n land, then P59-0 re-runs from p59-0-move.patch.
- 2026-09-25 ARCHITECT (N02 MOVE rows): the 18 cross-plane integration tests in crates/busbar-kernel/tests/ (and every *_cross_plane.rs) do NOT move into plane crates (plane test-reach ceilings forbid it). They stay where they are and stop NAMING planes: they get real planes through the SEAM-T test-linked registry — the build.rs-generated `$OUT_DIR/test_linked.rs` from `[package.metadata.busbar.test-linked]` (dev-dep crate list in Cargo.toml, not .rs) — and address each plane by its declared key/section read back from the registry, never by crate identifier or literal. K3 applies this after SEAM-T lands the generator.
- 2026-09-25 ARCHITECT (S11b (c), cites #49 OWNER-LOCKED + standing rule Q67): OPTION A. The kernel lifts only the top-level sections the REGISTERED planes declare. A build that compiled a plane out treats that plane's section as an unknown key and refuses with serde's standard unknown-field message — which is exactly what 1.5.5 did for any key it did not know (Q67: revert to 1.5.5). The bespoke "compiled without the plane that owns it" / "endpoint block is configured for a plane this build was compiled without" refusals REQUIRE the kernel to know plane section names it does not have, which #49 forbids; they are 1.6.0-only text in non-default builds. S11c (after K0 lands registry.rs): registry-driven lift list (oauth_as stays kernel-owned), kernel unit tests seed a neutral plane declaration, update config/tests/tests.rs:3985-4057 + scripts/proto-deletion-gate.sh:785,916,1007 + scripts/plane-delete-test.sh refusal_witness/judge_refusal to expect the unknown-field refusal (still asserting the process refuses and names the key). Flag in Q68 addendum.
- 2026-09-25 L2 residue (qa/unconstructed.toml, 27 unshipped rows, gate green as ledgered debt): breaker x4 (max_requests wiring refuses customer requests — item 142 breaker fold owns), audit signing (new config key), streaming deny-list (new StreamsCfg key), money PARKED-OWNER (pricer card, checkpoint seal/journal, adjusting entries, late accrual, multi-currency — multi-currency is DEAD per #66/Q4: strike it), plane/export plugin open (loader+root wiring — K1 covers the export kind's linked entry), 13 admin-verb effects (openapi regen §9.6). Triage slot UC-TRIAGE after the K/SD waves: map each row to its owning TODO item or rule it; none dropped silently.
- 2026-09-25 kernel_ceiling ratcheted 51799 -> 51744 (6217f879e).
- 2026-09-25 ARCHITECT: SD-0's O1–O13 ruled — see sd-extra.txt (binding for SD-1..SD-8). O9b (busbar-timing roster seat) queued to owner.
- 2026-09-25 ARCHITECT CORRECTION (UC-TRIAGE): my 2026-09-24 note (line 59) that all 13 admin-verb effects are 1.6.0 scope CONTRADICTS the owner's 2026-09-08 ruling (ARCHITECTURE §4.7: set_operator_key/set_escrow/set_dual_control/export_keyset/approve removed from 1.6.0) and #77(9). The owner wins; line 59 is struck. Of the 13, 5 are dead (owner 2026-09-08), 4 dispute/overdraft are dead by #77(9) pending the owner's Q5 confirmation (queued Q71), 4 survive (verify, plane_facts, plane_record_write, commit_upgrade) and need served paths + openapi regeneration (§9.6 owner approval, queued Q71).
- UC-STRIKE (now): delete dead code with no production caller, each deletion its own commit, striking its qa/unconstructed.toml row: multi-currency set_rate/set_fee (#66, Q4); adjusting entries (#77(2)(3), Q36/Q9); the 5 owner-removed admin verbs; the streaming deny-list (Q67: 1.5.5 had none); pricer with_card (superseded by from_card; no figure moves — prove with the money tests + oracle billing/ledger family).
- Owned rows stay with their items: breaker x4 -> item 142 (MUST land as the merge into the one live breaker — never a second gate); plane open -> item 63 (after stream-B 410); export open -> item 141.
- 2026-09-25 ARCHITECT (K4 residue, #2 rule (1), item 63): remaining same-path work, ordered: K6 (item 410 ABI minor/major + repr(C) PlaneDecl states every PlaneDeclaration fact) -> K7 (H6 part 1: the request loop drives a HOT-lane plane through the plugin path so a dropped-in plane SERVES, not just registers; generic raw-section carrier for any declared plane section; a real shipped plane built as cdylib per item 63) -> K5 (store/secret/auth/hook/export: each kind gets ONE registration function both doors call; built-ins become linked rows of the same axis). K5/K7 kernel lines: net <= 0 by collapsing the per-kind duplicate paths they replace; any unavoidable remainder waits for the SD-8 kernel re-arm (Q69(3)). CORRECTION: transport MUST be droppable — spec #3 (OWNER-LOCKED): a kind is 'swappable (compiled-in OR dropped-in over the ABI)' and TRANSPORT is one of the 7 kinds; the loader's 'transports are in-tree only' refusal (kind_refusal_tests.rs:31) contradicts #3 and is removed by K8 (repr(C) Transport vtable on the HOT lane #30, loader admits kind transport, same transport axis as K2e's linked rows). Export: owner ruling 2026-09-18 in #3 — the four built-in sinks become real both-ways export plugins over the COLD/JSON ABI, export-example-plugin then DELETED, bytes identical to 1.5.5 (oracle export/metrics) — that is item 141's scope, run as K9.
- L5 intake: busbar -> busbar-plugin-example-plane test edge [[dep]] row; busbar x plugin-tooling matrix row (K4).
- K6: plugin ABI now 2.22 (MAJOR bump for the BuildCtx resize, item 410). Post-promotion: plugin repos rebuild against it when re-pinning .busbar-ref (hot-lane only; cold-lane repos check their own preamble — verify at re-pin).
- 2026-09-25 ARCHITECT (K2c): capability-equality / teller-steps 'root legs' for mcp and a2a RE-POINT at the served rider (GauntletKernelUnit path) — the rider IS those planes' served root leg (same logic as R6); coverage is re-pointed, never retired. Features root-mcp/root-a2a go; scripts/ci/xtask feature lists follow. K2c2 applies the staged deletion patches + the re-point in consistent commits.
- 2026-09-25 ARCHITECT (K7 63(c)): a real shipped plane as cdylib is sequenced AFTER the contract merges (#84: plugin-sdk -> contract; roster "busbar-plugin MERGE" -> contract). Then a plane depends only on contract (#40) and gets the HOT-lane types + an SDK export macro from it. Unsafe rule for planes: `#![deny(unsafe_code)]` (not forbid) with exactly ONE `#[allow(unsafe_code)]` module — the macro-generated C-ABI export module behind the plane's `cdylib` feature; the plane's invariance test asserts unsafe appears ONLY in that generated module. Slot K7c runs after F6 + the busbar-plugin merge.
- 2026-09-25 ARCHITECT: K9 export extraction seams defined in k9-extra.txt (S1–S7); K9a host seams first, then K9b–K9e per sink.
- 2026-09-25 ARCHITECT (K5 residue): spec #2 (OWNER-LOCKED) itself prescribes the auth both-ways witness as steps (1)-(5), step (4) being the plugin-loader -> auth-static-plugin dependency and (5) auth_conformance_tests.rs — so kind-isolation's refusal of that edge contradicts #2; the export precedent's admission applies to every kind's fixture. qa/kind-isolation.toml gets [[dep]] rows for plugin-loader -> {auth-static-plugin, hook-test-plugin, secret-example-plugin} citing #2 steps (4)/(5); the withdrawn witnesses (k5-auth-hook-witness.patch) re-land. `keys` / admin-tokens are CORE's own token verify (core owns token stamp + auth verify on the hot path) — NOT auth-kind instances; the auth axis covers plugin auth modules only. Remaining built-in rows: store `memory` (patch, rebase after K9a), secret env/file, hook ranking strategies -> K5b.
- 2026-09-25 ARCHITECT (P68-0 residue): (a) durable::write does NOT move to contract — spec roster SPLIT row puts api `durable.rs` (real fsync path) in def 2 (kernel), and contract holds no I/O machinery (feature_invariance test stands). A plugin owns its own I/O: the structure-lint choke-point:bypass rule scopes to core/kernel-tier crates, NOT plugin-kind crates (a 3rd-party store writes its own files); store-example-plugin then persists with its own write (D2's inline) and drops the api edge. (b) sha256_hex/constant_time_eq: the libc-via-cpufeatures edge is exempted tree-wide in qa/construction.toml, so they move to busbar-contract IF `cargo xtask gate denylist` + construction stay green with sha2 in contract; else they stay and the owner item stands. (c) SecretRef merges with F1 (crate deletion + consumer repoint in one commit). (d) DW wave: one agent per breaching crate repoints to contract per P68-0's table and drops its api edge; sdk-macro edges close at F6 (#84).
- 2026-09-25 ARCHITECT (K5b 3c): the structural name rule governs a row's PACKAGE name; frozen config spellings (least_busy etc., RESERVED_HOOK_NAMES) are ALIASES of the one hooks-ranking row, resolved through the axis's alias table — no rename, no rule skip. Rows move from kernel preflight::linked_rows() to the root linked tables once K2c2 releases crates/busbar/Cargo.toml.
- VOICE-R4 residue for K2f: wire OpenToolCalls ending/closed on the served path (rows for answered/expired client-served calls are never freed) without breaking runtime/tests.rs::the_sweep_rides_the_pump_and_ends_with_it. Q72(1) note: default build shows NO change (EchoToolExecutor serves every tool).

### 2026-09-25 ARCHITECT RULING K9e (cites #3 owner ruling 2026-09-18: sinks become real export plugins, bytes identical to 1.5.5; Q67; #30 COLD lane; #40)
- K9e-1 (now): option 4 as a STEPPING STONE — move the OTLP layer code unchanged out of busbar-kernel into the composition root (crates/busbar), together with S7 so every commit nets kernel <= 51049. Bytes identical by construction.
- K9e-2 (then): the real busbar-export-otlp plugin. Option (a): the `traces` stream carries the FULL span record (all span fields/attributes, events, status, ns start/end, code location, thread, target, busy/idle) — a stream that drops what the 1.5.5 exporter sent is a defect (same principle as Q57/Q61 "a drop is a defect"). Option (b) (unprojected raw channel) is REJECTED — projection principle stands. The `fields:` refusal text MUST stay 1.5.5-identical: measure what 1.5.5 printed for `fields:` on an otlp instance; the refusal lists what 1.5.5 listed (Q67). Carriers: additive ABI minors for (i) binary request body on the S5 egress carrier, (ii) per-sink declared egress policy (the otlp sink declares its 1.5.5 policy — http loopback allowed as 1.5.5 did; the webhook policy stays the webhook sink's), (iii) host tick/flush op for batching + shutdown flush. Then the in-root OTLP layer is deleted.

### 2026-09-25 ARCHITECT RULING — FROZEN CUSTOMER TEXT vs the noun gate (cites Law "customer-visible identical", #47/#49, ruling 2026-09-25b)
The [pragma_ceiling] frozen_literal = 8 STANDS (no owner raise). 178 rows in noun-frozen.tsv are handled by category, not by pragma:
 (F-T) TESTS that assert customer-visible text (config keys, mount paths, headers, scopes, CLI flags, env vars, multi-line YAML fixtures) move those literals into FIXTURE DATA files (tests/fixtures/*.{yaml,txt,json}) that the test loads (include_str!/path) — the fixture IS the golden input, data not code; same precedent as 25b (scanner word lists -> fixtures).
 (F-P) PRODUCTION code outside a plane's family that spells a plane's frozen text is a #47/#49 defect: it reads the text from the plane's declaration/registry (the plane owns its section name, paths, headers), never a literal and never a pragma.
 (F-F) Rows inside the noun's own family are not leaks (verify each against the gate before acting).
 The 8 pragmas remain for the genuinely irreducible (e.g. a 1.5.5 operator message whose format string must carry a literal) — each pinned.
 Slot N-FIXTURE applies this to noun-frozen.tsv (files not owned by live slots); N-KERNEL applies it to its 16 withdrawn rows.
- K9d L5 rows: busbar->busbar-export-prometheus; kernel/core-admin->export-prometheus (test edges); matrix cells for the new crate.
- 2026-09-25 ARCHITECT (EX-DEL residue): export-example-plugin deletion WAITS on Q75 (the only 1.5.5 traces carrier is otlp; file/webhook may not declare traces — 1.5.5 refuses it). When unblocked: the both-ways harness names ONE fixture per real sink capability ([package.metadata.busbar.both-ways] export becomes a list: file for #11/S1–S4/start-check, webhook for S5/in-flight, prometheus for S6, otlp for S7 traces); cdylib finder learns real sink names; reference list in EX-DEL report. No partial move now (avoids churn).
- K9d gap: a first-party-signed prometheus sink DROPPED IN (not linked) never booted end-to-end at binary level -> fold into EX-DEL's per-capability conformance list. WARDEN: verify secret_ref_coverage at HEAD (K2e fixed in 8cea800c4; K9d still saw red).
- 2026-09-25 ARCHITECT (K8 residue): transport both-ways fixture dev-edge plugin-loader->busbar-transport-tcp is admissible (#2 (4)/(5), K5 precedent); rule 9 exempts only the crate named by [package.metadata.busbar.both-ways] for kind transport; K8 writes the rule + selftest + the one [[dep]] row.
- 2026-09-25 ARCHITECT (CI-FIX3 residue): plane-purity frozen-wire-claim on busbar-core-admin tests (OpenAPI key "responses") — the frozen-wire pragma is for CONFIG keys only; apply F-T: the OpenAPI key literal moves to a fixture data file the test loads; pragma removed -> WARDEN. kind-isolation ledger stale (dead edges/cells/voice alias) keeps preflight red -> L5-INTERIM now: strike dead rows + add ONLY rows backed by a recorded ruling (all "L5 intake" lines in decisions.md) + --write lowering; no raise. plane-delete-test --all voice control + decisions coverage -> WARDEN re-measure on a clean worktree.

### 2026-09-25 OWNER RULING — PLUGINS LIVE IN THEIR OWN REPOS (supersedes spec roster rows 16–40)
busbar repo = 15 core crates. Every plugin (all 7 kinds) lives in its own repo; default build pulls pinned versions. Fixtures deleted; real plugins are the both-ways proofs (auth: auth-github/ldap/oidc; secret: hashicorp-vault; export: export-*; store: store-memory + store-*; hook: hooks-ranking + headroom/webrequest; plane: plane-*; transport: transport-*).
ARCHITECT SEQUENCING: (1) finish in-tree folds INTO the plane/transport/plugin crates first (SD chain, F-folds, P59) — they are the unit of extraction; (2) then EXTRACT each plugin crate to its repo with history (git filter-repo --subdirectory-filter), one repo per plugin, pinned back as a git dependency in the root manifest's linked rows; (3) the in-repo loader conformance tests pin the real plugin repos as dev-deps; (4) CI 'consumers' job builds every pinned plugin against busbar predev. Creating new remote repos is outward-facing -> confirm hosting with owner.
OWNER (2026-09-25): "repo per plugin" + "mimics what we have today" -> template = store-mysql: workspace {logic crate, adapter crate}, .busbar-ref pin, own CI. Default build = pinned-version pull.
ARCHITECT (in-flight slots): K8c, SD-3, XPLANE, K2h, F14, F4-follow, KI-ROOT, WARDEN finish IN PLACE — they reshape the crates that become the extracted repos; extraction (EXT-*) runs after the SD/F fold chain lands per crate. No new in-tree plugin crates are created from here (K9e otlp -> export-otlp repo; fixtures -> delete).

OWNER 2026-09-25: create 12 plugin repos on github GetBusbar, same visibility as store-mysql, with extracted history. Q71(1): four verbs removed, code deleted.
OWNER Q71(2)(3)(4) all YES (recommended). Mode: unattended.
- 2026-09-25 ARCHITECT (WARDEN proto-llm row): (i) single-plane CI rows keep default non-plane features on (transport-tcp + export-prometheus/-file/-webhook), by root feature name. ARCHITECT (WARDEN exporter-list): the unknown-exporter refusal's module list is derived from the linked export axis; default build bytes are pinned identical (oracle cli/validate 0 diff); RED arm: a build without prometheus does not list it.
- 2026-09-26 ARCHITECT (DEC-SERVE finding): the generic HOT plane door lacks seams that EVERY plane needs once planes live in their own repos (owner move-out ruling). Rulings:
  G1 CALLER (kernel, #65/#40 zero trust): HostState carries the middleware-resolved caller as an opaque kernel handle, set by hot_dispatch from the auth context; meter_charge attributes ONLY to HostState's caller; any key id a plane writes in its Usage tail is ignored. RED: a plane writing a forged key id is billed to the real caller.
  G2 CARRIER (ABI, Part 3 WorkItem reserved-shape): append-only minor — request-head handle (method, path, query, headers) readable via accessor slots; reply emit gains status u16 + headers + body; bodies over MAX_PLANE_REPLY_LEN use the response-stream emit kind (IMPLEMENT row). Provider status/body pass through byte-for-byte. Lands AFTER F6.
  G3 EGRESS SCOPE (kernel): egress_open scope is derived by the host from OPERATOR-configured destinations (the plane's declared config section's destinations get the scope the linked planes get today for operator-configured upstreams); a plane-chosen URL stays public-https-only. No new config key. Loopback mock upstream configured as an operator destination is reachable in tests.
  G4 DEP WALL: #84 — no plane edge to plugin-sdk; export macro + HOT types come from busbar-contract after F6 (sdk+busbar-plugin merge into contract). DEC-SERVE resumes after F6+G1-G3.
  G5 /v1/models: ruling (a) stands — the decision plane declares NO claim on /v1/models; fix its declaration and the registry.rs seal-order doc. Typed `decisions:` boot refusals stay (plane-declared config section validation, S-SECTION carrier).
- 2026-09-26 ARCHITECT (UC-SEAL residue): checkpoint cadence = fixed constants 10,000 entries / 60 s (ARCHITECTURE §4.7), no config key; root wiring + #82 key source -> SEAL-ROOT.
- 2026-09-26 ARCHITECT (UC-HOLD): teller.rs per-file ceiling NOT raised (Q71(4) authorizes behaviour, not a ratchet) -> TELLER-SHED sheds >=36 lines. Note: no production Run passes parent Some today, so the conversion is inert on the live path (0 oracle diff); live refusal only where a door overrides at_parent_exit.
- Q41 regen list: +4 Q71(2) verbs (UC-VERBS: GET /verify, GET /plane-facts, POST /plane-record-write, POST /commit-upgrade; additive: +4 paths +10 schemas, 0 existing changed; measured patch busbar-run/ucv-openapi-regen.patch). Until regen: openapi_json_matches_committed_file + served_openapi_lists_only_the_configured_planes red.

- 2026-09-26 ARCHITECT (WARDEN exporter-list): the unknown-exporter refusal lists EXPORT_MODULES filtered to the modules the build serves (kernel's own + linked export-axis rows), frozen order. Default build = 1.5.5 bytes (pinned: crates/busbar/tests/export_unknown_module_lists_what_links.rs); a build not linking a sink does not list it. Correctness fix under Law 7 (default unchanged). Landed 82e5c98c4.
- 2026-09-26 ARCHITECT (K2i residue): feature `root-llm` is deleted (K2h made it co-enabled with proto-llm); root/units_llm.rs holds a plane-free node -> renamed root/plane_node.rs (tests too), gated on the generated linked node-axis cfg; every xtask gate/qa/ci/script reference re-points. Slot RENAME-NODE.
- 2026-09-26 ARCHITECT (WARDEN doc-links): busbar has no doc-links CI job (that is the freemkv pipeline); ~170 broken intra-doc links across 15 crates are NOT gated — no new gate added red-on-arrival; not a 1.6.0 exit leg.
- 2026-09-26 ARCHITECT G1b: admission identity from HostState caller only; host-internal mints carry ctx.gov caller; tail-key attribution path deleted (HOTDOOR-A continues). HOT-door G1 money fix: dropped-in plane billing now attributes to the resolved caller (was the plane-written key) — a correctness fix on a 1.6.0-only door, no 1.5.5 surface.
- 2026-09-26 ARCHITECT (FIX-DEL residue; owner FIXTURES ruling + #2):
  R-FIX1: every real plugin gets its dropped-in door (cdylib + contract export macro) — #2 requires it and the move-out needs it. Sequenced after F6 (slot DOORS, one agent per kind: plane, hook, store, export, transport-already-done).
  R-FIX2: dropped-in door proofs use REAL plugins: hook -> webrequest-hook against a local mock upstream (reject/restrict/sleep via upstream replies); store -> store-sqlite (durable file, restart, flock); auth verify -> auth-oidc with a local JWKS (mcp_stdio_serve + plugin_chain tests present a signed JWT instead of a static bearer); export traces -> export-otlp (Q75); plane -> the real plane crates once their doors land.
  R-FIX3: behaviour doubles the kernel's own tests need (configurable panic/sleep/nack/raw-reply hook, durable store double) live as in-crate test-support modules of the crate under test, LINKED only — not workspace crates, not examples. Fault-injection that must cross the dlopen boundary (a plugin that panics/aborts) is a test-built cdylib generated inside plugin-loader/tests at test time, not a roster crate. [owner-visible note: these are not 'example plugins'; flagged in summary]
  R-FIX4: external plugin repos port to busbar-contract (PORT-EXT) AFTER F6 lands (sdk disappears in F6; porting twice is waste). FIXDEL-*-port.patch are the starting point. Push to each repo's dev branch.
- 2026-09-26 ARCHITECT (LEDGER-TIDY queue): busbar-core-admin (and busbar-oauth2, busbar-core-connsec) resolve as kind `cleanliness` (spec: admin/oauth2 are cleanliness crates, always compiled in, one-way dep on core); gate grants (root, cleanliness) and (cleanliness, core); root -> core-admin row becomes allowed citing it. -> WARDEN.
- 2026-09-26 ARCHITECT (UC-VERBS): openapi.json regen committed alone for Q71(2) — pure addition (+648 lines, 0 removed); owner Q71(2) explicitly approved the regeneration. Follow-ups: D-3 idempotency on the two writes; plane-declared record kinds gate plane_record_write.
- 2026-09-26 ARCHITECT G1b (DEC-SERVE, admission side of G1; #65/#40 zero trust), implemented by HOTDOOR-A in 2ff751f2e + aa729bdd9 (money, alone): ONE attribution rule — govern_admit / govern_admit_reason admit, and meter_charge bills, ONLY HostState's caller (the middleware-resolved key the minter stamps); the Facts identity tail and the Usage tail key id are never read as a key (tail-key billing/admission paths deleted). Every production metering/admission mint carries the caller: BudgetHost::meter_charge(scope, caller, usage) and EngineHost::govern_admit_reason(scope, caller, pool) take the request's PlaneRequestCtx; mcp charge_round and a2a admitted/meter_request/HopCharge pass ctx.gov (same key they wrote into the tails, so linked rows/admissions unchanged). A mint with no caller (with_borrowed_host_as) admits as govern::SYNTH_TENANT_KEY "plane:tenant:<tenant_id>" and bills govern::SYNTH_ADMISSION_KEY "plane:admission:<admission>", each a named constant with a test. Oracle http.crosscut/llm/billing 167 PASS 0 DIFF (mcp/a2a cells are UNBASELINED on the golden — proven by their crate suites, green).
- 2026-09-26 ARCHITECT (SEAL-ROOT queue; #82(a) key source; ARCHITECTURE §1.2 + PB-13; owner 2026-09-08 cut export_keyset): the deployment keyset (audit + checkpoint signing, one keyset) is minted at the first boot's Bootstrap and SEALED IN THE STORE where the store can hold it (native-ABI store); on a store that cannot (1.5.5 ABI-2 store, memory store) it is node-local and ephemeral (PB-13) — nothing depends on it. With data_dir written: the keyset file under data_dir (0600) is a local cache of the store-sealed keyset; KeysetMissing fires only with data_dir set when a Bootstrap exists and neither the file nor the store yields the fingerprint; its remedy text names restoring data_dir or a store that holds the keyset. NO off-node keyset import/export CLI in 1.6.0 (export_keyset was cut by the owner, so import has no source). FLAGGED to owner as Q78.
- 2026-09-26 ARCHITECT (checkpoint retention): in-memory Durability.checkpoints is a bounded ring of the latest 1,024 seals; the journal is the durable record; #82(d) head history (~100 B/head) is retained forever independently. The checkpoints read serves the ring.
- 2026-09-26 ARCHITECT: kernel ceiling pinned 51049 -> 50846 (measured 50773 + K2g <=73); SD-8 (R-KERNEL/Q69(3)) re-arms in its own commit with its own figure; TIMING-FOLD re-arms by moved lines (Q70); all other slots net <=0.
- 2026-09-26 ARCHITECT: codec tests reach busbar-contract (+ contract testkit O8) only — the codec moves out with its plane; kernel-equality proofs live kernel-side; no use-collapse (SD-3).
- 2026-09-26 ARCHITECT (no-response-escapes-audit): a plane unit answers PlaneAnswer (#28); Response is made on the root's audited exit; sole exemption = PlaneAnswer::Live constructor, in the rule's scope (NODE-AUDIT).
- 2026-09-26 ARCHITECT (cleanliness kind, WARDEN Q): option (a) — admin/connsec/oauth2 = cleanliness (spec :3780 R2/#37); grants (root,cleanliness),(cleanliness,kernel); empty `core` kind struck; plugin<->cleanliness refused both ways. Kernel reserve for K2g now 59 (14 spent by G1b + plane record kinds).
- 2026-09-26 ARCHITECT (SD-3 queue):
  (1) anthropic S2-a: the egress declaration gains an append-only `static_headers: &[(&str,&str)]` field (contract shape); the kernel egress engine writes declared static headers verbatim; anthropic declares its scheme + `anthropic-version`; byte-identical upstream requests (oracle llm family). -> SD-3b.
  (2) S2-b/O11: ACCEPTED as built — the translate cap reaches the codec through a host-installed reader via the contract (all 4 reads are response-path; EgressPrep is request-path). No EgressPrep field.
  (3) operator log parity: the kernel egress rows emit the SAME warn text the deleted bedrock builder emitted for an unencodable session token (and bearer invalid-byte diagnostics keep their 1.5.5 text) — logs are operator-visible, Law 7. -> SD-3b.
  (4) O8: contract testkit ships as an always-compiled `busbar_contract::testkit` module (pure shapes + in-memory doubles, no I/O, no feature) — feature_invariance stands; codec drops its warn_capture copy. -> SD-3b.
  (5) codec x plane 736->862 and codec x transport 616->777 are MOVED text (substrate-values -> codec, the #83a direction) — handled under owner Q77 (re-arm at final pass after audit); dead dep rows/cells struck by lowering now (WARDEN/L5).
  (6) dropped-in planes get host services (entropy, clock, usage-tap latch, translate-cap reader) through HOT host vtable slots — lands with HOTDOOR-B (G2) after F6.
- CI: predev pushes do NOT trigger ci.yml (branches filter); architect dispatches ci.yml on predev after each batch. Run 36236344546 dispatched at 1bd154d41.
- 2026-09-26 ARCHITECT (UC-VERBS follow-up): ACCEPT the assumptions — 1.6.0-only writes refuse a reused Idempotency-Key with a different body (409 new text; the 1.5.5 key-mint replay-any-body parity stays on its own verbs); header optional; undeclared record kind = 403 per contract §7.3. HOT ABI minor now 29.
- 2026-09-26 ARCHITECT: ceiling-slack accepts NAMED reservations (declared row citing its ruling, subtracted before judging slack; unnamed gap stays RED). CI 36236344546 @1bd154d41: red = structure-lint(hybrid, fixed 3fb47edcd), ship-ready(ceiling-slack/rose/ship-twin), llm-spec (skipped oracle), umbrella; preflight/build-release/shadow skipped. -> WARDEN P1.
- 2026-09-26 ARCHITECT (KEYSET): store half has NO carrier (kinds::Store record_put/get only at STORE_ABI 5, above the window) — built: ephemeral + data_dir cache. Oracle admin.ops|GetAuditKeys|ok diverges (keys now published) and admin.ops|GetLedgerCheckpoints|ok will diverge past the 60 s cadence: both register as owner-mandated by spec #82 (owner-locked 2022-09-22: core signs; admin API exposes head/range/PUBLIC KEY SET) — registration slot ORACLE-REG; cited in Q78.
- 2026-09-26 ARCHITECT (EXT-PILOT): template = busbar-run/ext-recipe.md. Next: EXT-EXPORT (prometheus, webhook — existing scaffold repos) now; store-memory, hooks-ranking after F6 + R-FIX1 doors; transports + planes after F6/HOTDOOR-B + fold chain. Post-F6 every extracted repo re-pins sdk->contract.
- SD-8 note (SD-5c): SD-8 removes BUSBAR-7104 from host REGISTRY and adds it to busbar_a2a::DIAGNOSTICS in the same commit (no double listing).
- 2026-09-26 ARCHITECT (SD-5a): accepted — import grouping kept ports-only:busbar-llm at 253 while renaming substrate->kernel paths (same reach, renamed; not new coupling). Standing target: a plane crate moving to its own repo has ZERO busbar_kernel reach (#40 dep wall, owner move-out) — every remaining kernel item a plane names becomes a contract host service (HOTDOOR-B) before extraction; ports-only:<plane> ceilings drive to 0 by EXT time.
- 2026-09-26 CORRECTION (architect): my KEYSET line claimed GetAuditKeys "diverges" vs 1.5.5 — WRONG: 1.5.5 has no /audit/keys or /ledger/checkpoints route; both cells are UNBASELINED (accepted-gaps admin-kernel-verbs-new-in-1.6.0). Admin family vs 1.5.5 golden: 0 unaccepted divergences. No accepted-differences entry; judged at the 1.6.0 golden cut.
- 2026-09-26: ports-only + ports-only-tests RED for busbar-mcp and busbar-a2a after SD-5b/5c re-paths -> back to SD-5b/5c: contract host services (clock etc.) instead of busbar_kernel::, no ceiling raise, no use-collapse of NEW reach.
- 2026-09-26 ARCHITECT (WARDEN A/B): (A) choke-point:bypass joins STRUCTURE_LINT_STANDING_REDS tied to F6 (struck in F6 commit). (B) ship-ready is not in umbrella needs by design (ci.yml:4058; KICKOFF §13.4 required on qa/main only; 13.4 was not carried into the TODO rules) — report-only on predev. Heavy-fold unlock = umbrella green + shadow oracle ran with 0 divergences.
- 2026-09-26 ARCHITECT (F14): transport-key provisioning home = roster def 3 busbar-kernel-identity (#36). `unit` KindDef RETIRED in the gate (spec: unit is not a kind). F14 authorized to land crate deletion incl. gate-owner files (lowering/striking only). kernel-identity cell rises are moved text -> Q77.
- CI dispatched: run 36239844145 at f0cc8417e (includes WARDEN 1aa563696 preflight-green HEAD + SD-5b follow-up).
- 2026-09-26 ARCHITECT (SD-3b N4): option (b) — split the root protocol_registry/detection tests: synthetic-declaration tests -> busbar-kernel; real-declaration tests -> root unit tests over the linked table, literals in a fixture (F-T). No ceiling re-arm.
- 2026-09-26 ARCHITECT: ceiling-rose treats a declared raise whose `to` == base value as expired-silently (PASS + note); RED stays for never-moved/mismatched/undeclared (WARDEN implements).
- 2026-09-26 ARCHITECT: kind-isolation CI step -> --posture with :deps/:test-deps/:closure/:matrix STANDING, excused only for findings in a committed snapshot (ratchet: any new edge/cell/rise/count-above-snapshot is RED; vanished findings reported + struck via --write). Other KI rows stay blocking. (WARDEN implements.)
- 2026-09-26 ARCHITECT: core tiers -> contract is GRANTED (#83/#83a shapes crate; #40); kernel×contract ratchet + unlisted kernel->contract leave the standing snapshot. RED kept: plugin reaching non-contract; contract depending on any busbar crate.
- 2026-09-26 ARCHITECT (F6 queue):
  (1) RATIFIED: busbar-contract is #![deny(unsafe_code)] with exactly ONE #[allow] module (`pub mod abi`, the C-ABI door/boundary); feature_invariance pins that structurally with RED arms. Same rule as plane crates.
  (2) plugin-sdk compat facade stays ONLY until the three export repos re-pin to busbar-contract (slot EXT-REPIN); then crates/plugin-sdk is deleted in the same busbar commit that bumps the pins.
  (4) contract holds SHAPES + macro definitions only (#83). abi::sdk::hostlog: logging is a HOST SERVICE — contract declares the shape; the eprintln fallback is deleted (no host installed => plugin logs drop, never print); the tracing-dispatcher install moves into the export macro's generated code (it runs in the plugin binary, not in contract). CountingAlloc #[cfg(test)] may stay. -> CONTRACT-PURE slot.
  (5) KI rows relocated by the merge are MOVES (plugin-sdk/busbar-plugin -> contract): WARDEN re-keys them in the standing snapshot as moves, net across the merge <= before; a genuine new edge stays RED.
  (6) loc-ceilings:union +5257 is moved lines into contract (Q50 standing; contract re-armed per Q68(3)) — stays in CONSTRUCTION_STANDING_REDS until the Q50 union ruling is revisited at L5.
- 2026-09-26 ARCHITECT (F6 KI re-key): (i) plugin-tooling -> contract joins CONTRACT_TIERS (loader names the ABI where it lives, #84); (ii) legacy engines' +49 contract naming re-keyed as F6 moves. SD-8 spawned (kernel landing + delete substrate-values, Q69(3) re-arm).
- CI dispatched at WARDEN-green HEAD (see run list).
- 2026-09-26 ARCHITECT: /metrics nondeterministic order fixed in the export-prometheus sink (owns rendering), sorted families+samples, after EXT-REPIN. GetAuditKeys key_id normalization = busbar-release engine patch (prepared, NOT pushed — owner repo) -> owner queue.
- 2026-09-26 PB-65: NOT a regression (v1.5.5 wire always passed a mode; both-headers arm was test-only). ARCHITECTURE.md PB-65 text corrected; WARDEN re-cites.
- OWNER QUEUE (busbar-release, not pushed): busbar-run/oracle-auditkeys.patch (json.audit-keyset scoped normalization, tested); env-dependent oracle test drive_binary_and_ping_is_byte_identical_to_python fails in local clone with/without patch.
- ACCEPT: testkit/warn_capture.rs record-nothing set_global_default is the one named contract output exemption (O8 test double).
- CI run 36279754843 dispatched at d2b7d5ca2 (includes branch-sweep identity fix 2fd4f679a + EXT-REPIN).
- 2026-09-27 ARCHITECT: auth-admin-tokens is a REAL auth plugin -> gets door + both-ways conformance (the AUTH kind proof) + extracted to GetBusbar/auth-admin-tokens, pulled pinned under its current feature. New slots: DOOR-TRANSPORT (http/tls/ws/stdio doors), EXT-TCP, EXT-AUTHADMIN.
- 2026-09-27 ARCHITECT (DOOR-TRANSPORT ABI appends; Part 4 Axis 1 "a new carrier is an append-only minor bump: a vtable slot at the end"; Axis 3 "kind is data"; #30 HOT lane; #40(b) opaque config; #65 zero trust; owner-ratified "core never knows what http means"). All names protocol-neutral (neutrality witness). Append-only at the END of the transport vtable, one ABI minor per append (take the next free minor at land time; rebase after HOTDOOR-B if it holds the hot module), each append re-points no-deferral waivers in the same commit, each gets a contract re-arm per Q68(3) in its own commit:
  T1 encode_envelope(state, fields_pod, body, out, out_len) — the transport frames its own envelope.
  T2 poll_read_frame(state, conn, token, buf, len, &mut FrameMeta{len, end_of_frame:u8, status_class:u8, status_code:u16, retry_after_secs:u32, flags}) + decl fields STATUS_CLASS and STATUS_NAMESPACE appended to the transport decl; the root reads them from a dropped-in row exactly as from a linked one. MONEY PATH (fee decision's status leg): lands ALONE (§8), with a linked-vs-dropped-in fee-decision parity test and a RED arm (the byte-count-only read).
  T3 poll_write_frame(state, conn, token, buf, len, end_of_frame:u8) — message completion marked on the last chunk.
  T4 poll_close_reason(state, conn, token, reason:u8) — reason is the contract's existing close-reason repr(u8); poll_close stays.
  T5 host config services on the transport host vtable: config_cert_chain(cfg, out), config_trust_anchors(cfg, out), config_sign(cfg, scheme:u16, msg, sig_out). The private key NEVER crosses the ABI; the host signs (#65). Plus conn_facts(state, conn, &mut ConnFacts{sni, alpn, peer_cert}) on the plugin vtable.
  T6 detach(state, conn, &mut Handoff) / adopt(state, &Handoff, &mut conn): the handoff is a host-owned raw byte-channel handle plus leftover bytes. The host moves it between transports; no transport names another (kills the ws->http edge).
  T7 connect_dest(state, &DestPod{kind: Authority|Program, authority | program+argv+env}) — subprocess is egress data, not a separate capability (Axis 3).
  Per-door exit: both-ways conformance (linked vs dlopen, byte compare, RED arm kept), a #30 crossing measurement < 1µs, oracle green.
- 2026-09-27 OWNER DIRECTION ("a transport abi redesign is better than hacking and patching") -> ARCHITECT RULING TRANSPORT-ABI-V2, SUPERSEDES the T1-T7 append ruling above. Root cause: the transport HOT ABI was shaped from tcp (an untyped byte stream), not from the linked Transport trait, so every other transport fell off it. Rule: the transport HOT ABI is a MECHANICAL repr(C) LOWERING of the linked Transport trait — one slot per trait method, nothing tcp-shaped, no duplicate old/new pairs. Pre-release, the only consumer is GetBusbar/transport-tcp (re-pins). One transport-ABI major bump; no parallel v1 kept.
  Plugin vtable: decl{key, composes_over, session, status_class, status_namespace, facts_mask}; listen(state, cfg)->listener; connect(state, &DestPod{Authority|Program+argv+env}, cfg)->conn; detach(state, conn, &mut Handoff) / adopt(state, &Handoff)->conn (host-owned byte-channel handle + leftover bytes; host moves it, no transport names another); poll_read_frame(state, conn, token, buf, &mut FrameMeta{len, end_of_frame, status_class, status_code, retry_after_secs, flags}); poll_write_frame(state, conn, token, buf, end_of_frame); encode_envelope(state, fields, body, out); conn_facts(state, conn, &mut ConnFacts{sni, alpn, peer_cert}); poll_close(state, conn, token, reason:u8). A byte-stream transport (tcp) is the degenerate case: end_of_frame per read, zero meta.
  Host vtable: wake; config_cert_chain(cfg); config_trust_anchors(cfg); config_sign(cfg, scheme, msg, sig_out) — the private key never crosses (#65).
  Removed: poll_read, poll_write, the authority-only connect, the reason-less poll_close.
  Witness: a trait-to-vtable coverage test (every Transport trait method has exactly one slot, RED when a method is added without one). Per-door exit: both-ways conformance, linked vs dlopen, RED arm kept; #30 crossing <1µs; oracle green. MONEY: the status leg (FrameMeta status_* + decl status_class and status_namespace consumed by the fee decision) lands in its own commit, with a linked-vs-dropped fee-decision parity test.
- 2026-09-27 ARCHITECT CORRECTION to TRANSPORT-ABI-V2 (owner: "tls — we spoke about transport con[nsec], this has been discussed specifically"). Governing: #40(b) "the kernel reads the secret, audits, builds the rustls config, hands the transport plugin an OPAQUE config handle it can use but not disassemble"; #36 key provisioning is kernel-side machinery, never a plugin; roster note BUSBAR-1.6.0.md:3885 "never sees a key byte", "make it impossible". The host services config_cert_chain / config_trust_anchors / config_sign are STRUCK: they hand the plugin certificate material and a signing oracle. REPLACEMENT: busbar-core-connsec builds the ConnectionSecurity (rustls config) host-side, and the plugin holds only its opaque handle (WireConfig). The handshake and record crypto run on the HOST side of the ABI through that handle: host vtable connsec_secure(handle, side: Accept|Dial, server_name_pod, &Handoff byte-channel) -> secured channel handle, and connsec_facts(secured, &mut ConnFacts{sni, alpn, peer_cert}). The tls plugin owns composition and lifecycle over the byte channel, and reports facts; it links no rustls and no key type. There is no byte accessor on the handle (#40(b)). Witness: the plugin's dependency closure contains no rustls or key type, plus a RED test that no ABI slot returns key or cert bytes to a plugin.
- 2026-09-27 OWNER-APPROVED (AskUserQuestion, both "Approve (Recommended)") — TRANSPORT-STACK. SUPERSEDES TRANSPORT-ABI-V2 and its connsec correction.
  (1) TLS = CONNSEC, core-only. busbar-core-connsec is the ONE TLS path, inbound (tls:) AND outbound on the raw-connection tier (providers: trust anchors / SPKI pin / mTLS client identity via kernel-identity). It never crosses the ABI. No plugin holds a key, cert, rustls type or signing oracle. DELETE busbar-transport-tls and kernel-identity/transport_key (TransportKeyHandle, TransportConfigSink tls path). Transports 7 -> 6 (tcp, stdio, http, ws, sse, grpc). The GetBusbar/transport-tls repo is never created. The spec #3 transport list is updated.
  (2) CORE STACKS. Two roles, one transport kind, role derived from COMPOSES_OVER (empty = CARRIER):
     CARRIER (tcp, stdio): listen/accept, dial(&DestPod{Authority | Program+argv+env}), read, write, close(reason), arrival facts (local/peer addr). Poll-shaped with the host waker.
     FRAMER (http, ws, sse, grpc): sans-IO state machine, no socket, no waker: open(side, conn facts) -> fstate; ingest(fstate, bytes) -> frames out with FrameMeta{stream_id, end_of_frame, status_class, status_code, retry_after_secs}; emit(fstate, frame, end_of_frame) -> bytes; encode_envelope(fields, body); refusal(stream, refusal); close(reason) -> bytes; detach -> leftover bytes (the upgrade); adopt(leftover) -> fstate.
     Core builds each connection as carrier -> [connsec wrap if the binding says TLS] -> framer, and moves the byte stream on an upgrade. No transport names another: delete every transport->transport dep edge (grpc->http, grpc->tcp, sse->http, ws->http, ws->tcp; the tls edges go with the crate). Decl carries every TransportMeta constant the root reads (key, composes_over, session, framing, selector forms, handoff/upgrades_to, status_class, status_namespace, transport_facts). The root reads a dropped-in row exactly as it reads a linked one.
  (3) The HOT ABI is a mechanical repr(C) lowering of the CARRIER and FRAMER traits, one slot per method. Witness: a trait-to-slot coverage test that goes RED on a missing slot. Pre-release, one transport-ABI major; the old poll/decl surface is removed (no v1 kept). GetBusbar/transport-tcp re-pins.
  (4) Config as ruled 2026-09-20: providers = the transport kind's connection catalog; tls: inbound = kernel section; connsec reads both.
  (5) Exit per transport: both-ways conformance (linked vs dlopen, byte compare, RED arm kept); #30 crossing <1µs per carrier and framer crossing; oracle green (unpinned ports); KI posture no rises; transport->transport edges = 0 (kind-isolation). MONEY: the fee decision's status leg (FrameMeta status + decl status_class/namespace -> kernel settlement FeeEvidence.status_at) lands in its own commit with a linked-vs-dropped parity test.
- 2026-09-27 ARCHITECT (WARDEN queue): (3) qa-names name-floor -> option (b): count the TOML half only, floor 300, re-measured in the comment. It is a reads-nothing detector, not a quality ratchet; the plant's premise already says so. (5) diagnostics catalog -> option (b): the page also reads the declares.json of every default-linked external plugin from its pinned checkout (cargo metadata). No operator-facing code leaves docs; OTLP's codes are added. (4) continue the bisect.
- 2026-09-27 ARCHITECT (DOOR-STORE queue): both-ways-fixture grant for the COLD kinds, mirroring transport's existing grant: plugin-tooling -> <cold kind> is allowed ONLY as a [dev-dependencies] edge whose sole users are *_conformance_tests. It is written in kind_isolation.rs with a RED plant (a normal-dep edge still fails). This is spec #2's witness shape, not a widening of the plugin->kernel wall. Land the loader both-ways patch.
- 2026-09-27 ARCHITECT (PORT-EXT-B queue): new slot LOADER-STAGE for the Linux /proc/self/fd staged-image reuse defect (a replaced plugin can run the old bytes; supply-chain integrity, #40 code-signing). store-valkey fork-refusal (was overwrite) -> OWNER FLAG Q79 (correctness fix aligned with store-sqlite; external plugin behaviour change). Plugin-repo release workflows -> new slot EXT-RELEASE to finish porting (release, release-on-upstream, docker) in all 6 repos.
- 2026-09-27 ARCHITECT CORRECTION to TRANSPORT-STACK count: sse and grpc are already wires inside busbar-transport-http (Q68(1) fold). After the tls deletion there are 4 transport PLUGINS: tcp, stdio (carriers); http (framer entry claiming the http, sse and grpc schemes), ws (framer). ONE ENTRY PER PLUGIN: a plugin exports one carrier or one framer entry, and the schemes are its claims (core asks "who handles X?"; a duplicate claim fails boot). The http crate's 3 separate `impl Transport` collapse into one framer entry dispatching by claimed scheme, like a plane's N dialects.
- 2026-09-27 ARCHITECT (WARDEN (4) kind-isolation-ship exemplar): option (a) — busbar-transport-tcp becomes the transport exemplar, so entry-count is enforced again. The http "implements Transport 3 times" finding is a real finding, ledgered as the Q68(1) fold consequence with its drain named: TRANSPORT-STACK's one-entry-per-plugin rule. It drains to 1 when the http framer entry lands. The plants stay on tcp.
- 2026-09-27 ARCHITECT (PORT-EXT-A): the AUTH kind now has a real both-ways witness — plugin-loader auth_conformance_tests on GetBusbar/auth-oidc (linked vs dlopen), spec #2's missing witness closed by a real plugin, not a fixture. KI strikes -> WARDEN; the mcp_stdio_serve 1/7 flake -> WARDEN root-cause; the 4 repos' release workflows -> EXT-RELEASE.
- 2026-09-27 ARCHITECT (EXT-RELEASE queue): (1) consumer-verify@dev and (3) scheduled runs reading main's workflows both resolve at plugin-repo promotion — logged, no action now. (2) wrong bundle_image and valkey prefix = defects, fixed. (4) release-on-upstream detects by commit sha, not by version string.
- [Stripping mechanism SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists": the auth names its credential lines and the transport strips them.] 2026-09-27 ARCHITECT (HOTDOOR-B queue 1, CRED-STRIP): a plane — linked OR dropped-in, identically — never sees the caller's credential. Governing: #65 zero trust, #40(b) (no raw secret to any plugin), the 2026-09-20 ruling "plane passes a credential-REF, never plaintext", and core owning auth verify. The host strips every header the auth gate consumed (the credential headers) from PlaneReqCtx.headers and the HOT head accessor before the plane sees the request. 1.5.5's UpstreamCreds::Passthrough (forward the caller's credential upstream) is served HOST-side: at egress the host injects the caller's verified credential when the pool's upstream_credentials = passthrough. The upstream bytes stay 1.5.5-identical (oracle-gated: passthrough and own cells). Witness: a plane that echoes all its headers gets no credential header, in both doors, with a RED arm; plus a passthrough cell showing the upstream receives the caller's credential byte-for-byte.
- 2026-09-27 ARCHITECT (HOTDOOR-B queue 2): HOT dispatch on spawn_blocking is a per-request thread hop on the #30 hot lane. Measure it (p50/p99 added latency per request, linked vs dropped). If the plane call is non-blocking by contract (blocking-ffi gate), dispatch inline on the worker; keep spawn_blocking only for a plane that declares blocking. Exit: the #30 crossing stays under 1µs, with the numbers recorded.
- 2026-09-27 ARCHITECT (HOTDOOR-B queue 3): no stated head -> result-class status + application/json, unchanged = correct (1.5.5 shape).
- 2026-09-27 ARCHITECT (EXT-TCP vs exemplar): e86acba07 made busbar-transport-tcp the KI transport exemplar. When tcp is extracted, the exemplar stays measurable: read from the pinned external checkout (cargo metadata), or the remaining in-tree single-entry transport. The transport kind is never left unmeasured.
- 2026-09-27 ARCHITECT (WARDEN (A), KI posture RISEs): NOT Q77 — Q77/77a cover moved text and measurement corrections, and these rises are NEW code. §9.2 applies: no ratchet raised. DRAIN:
  (i) 602933cc0 (K9e-2 carriers) cells busbar×plugin-tooling 168->182, busbar×transport 864->877, contract×transport 588->599 and loader×transport 92->120 are owned by DOOR-TRANSPORT. Its slot deletes the old Transport trait, poll slots and adapter. Exit: each cell <= its standing value, measured in the slot's final commit, with the snapshot lowered in that commit.
  (ii) 715cb1e2a (plugin-proofs) cells loader×plane 111->123 and loader×transport 120->124 go to WARDEN now: drain at the root (test-side vocabulary routed through the plugin-artifact data rows, as auth did), never by rewording to dodge the matcher.
- 2026-09-27 ARCHITECT (WARDEN (D)): approved. The stdio fixture writes providers/models only when the plane that owns them is linked (Law 7; mirrors thread_per_core_serves.rs). Bisect, then land.
- 2026-09-27 ARCHITECT (CONFIG-REQ; WARDEN finding): a build without the plane that owns a config section must not REQUIRE that section (Law 7; mirror of Q69(1), which refuses a compiled-out plane's section). Required-ness is declared by the owning plugin through the config-verb dispatch (2026-09-20 ruling: plugins declare CONFIG_VERB; core deals out sections and names none): `models` is required iff the plane that owns it is linked; `providers` (transport kind's connection catalog) is required iff some linked plane declares that it consumes providers. The default build (every plane linked) keeps 1.5.5's exact bytes for the missing-field error (oracle config cells). The kernel names no plane.
- 2026-09-27 ARCHITECT (WARDEN, 715cb1e2a loader cells): (a) APPROVED as a gate PRECISION fix, the Q77a class (measurement correction). An identifier exported by busbar-contract is the contract's own shape; naming it is naming the contract, not a plugin instance, so the matrix does not count contract-exported identifiers (e.g. RoutingDecision) as instance vocabulary. RED plant: a NON-contract identifier carrying the same word still counts. The standing snapshot is LOWERED to the new measurements in the same commit. The 3 prose hits are NOT reworded; they stay counted, and the cell nets below standing (123-23=100 <= 111). The 4 loader×transport hits (webrequest mock upstream) are held under DOOR-TRANSPORT's cell exit: loader×transport must end <= 92 including them. (b) rejected (moving to dodge).
- 2026-09-27 ARCHITECT (OTLP report): the oracle admin.ops|GetAuditKeys|ok FAIL is the ephemeral per-boot audit key id — owned by Q78 (keyset source) and the owner's busbar-release oracle-auditkeys.patch, not a code regression. New slots: HEAD-REDS (export_plugin_dropped_in_serves 2/3 + root::registry dropped-in wire 2, red at HEAD) and EX-DEL (delete export-example-plugin onto real sinks).
- 2026-09-27 ARCHITECT (DOOR-STORE leftover): the instance-noun-neutrality 'store' noun whose family was store-example-plugin is RE-POINTED to the real in-tree store instance (busbar-store-memory), never struck — striking would weaken the gate. -> WARDEN.
- 2026-09-27 ARCHITECT (WARDEN store-noun): (i) now — token `store_memory`, the 7 genuine hits land as [[leak]] rows (category core/composition-root) naming their drain; then (ii) is the drain, in slot STORE-DEFAULT: the kernel stops holding config::GOVERNANCE_STORE_MEMORY; the default governance store is the linked store row that DECLARES itself the default (a decl bit on the store plugin), and root resolves it. The config value "memory" and 1.5.5 bytes are unchanged (oracle config cells). The kernel names no store instance.
- 2026-09-27 ARCHITECT (posture rises at HEAD): each slot drains its own. TLS-RETIRE busbar×plane +10; OTLP (98ceb0679) busbar×plane +5, busbar×plugin-tooling +4, busbar×export instance 11->13, and the vendor-name finding in export_otlp_delivers_spans.rs; HOTDOOR-B (d4ef64111) busbar×plane +1, busbar×plugin-tooling +9; DOOR-TRANSPORT (1730b098a) contract×plane +1, contract×cleanliness 1->2 and its edge, plus the 602933cc0 cells; WARDEN 55cbca67d busbar×plane +1 and kernel×plugin-tooling +1 (attribute it first). New standing rule in wave-r.txt: a slot is not done while posture shows its own rises.
- 2026-09-27 ARCHITECT (re-attribution): busbar×plane +11 is c3e2fd685 (WARDEN's fixture), NOT 5b783c8a4 (TLS-RETIRE measured it at 0); +4 is 98ceb0679 (OTLP); +1 is 55cbca67d. Rule: attribute rises per commit with a before/after measurement, never by eye.
- 2026-09-27 ARCHITECT (DOOR-TRANSPORT step 3): (a) APPROVED — contract transport::Connection is the core-side stacked-connection interface (no Plugin supertrait, no key-handle params, no cross-plugin adopt); its ONLY implementor is the plugin-loader stack (a KI plant: impl outside the loader is RED); kernel and kernel-egress use dyn Connection; TransportConfigSink/Handle/ConfigRole and TransportKeyHandle are deleted. Plugins implement exactly one of Carrier|Framer.
- 2026-09-27 ARCHITECT (TLS-RETIRE queue): CG-49 multi-certificate SNI (SniCertResolver) retired with transport_key — it had no config path and no production caller (the tls: block names one certificate), so no customer surface is lost. Recorded as an OWNER FLAG (informational).
- 2026-09-27 ARCHITECT (OTLP follow-up): ACCEPTED. Refusal goldens captured from the PUBLISHED v1.5.5 binary (tests/v1.5.5-validate, capture.sh pinned to 1.5.5) replace hand-typed strings: this is the preferred pattern for any 1.5.5 byte-identity test. Vendor vocabulary moved to a data fixture is the sanctioned data-row route (same as auth), not a dodge.
- 2026-09-27 ARCHITECT: CI dispatched on predev 2d1ad6a13 (run 36320150019, LK). Full-cycle verification moves to LK runs instead of 80G local cycles (disk). WARDEN reads the run.
- 2026-09-27 ARCHITECT (contract +1271 breakdown): ACCEPTED. hot/transport.rs +399 (the row carries all 15 TransportMeta fields + byte vocabularies + crossing shapes); sdk/transport.rs +867 (one generic guarded bridge per trait method + export_carrier!/export_framer!, replacing an ~880-line hand-written hot.rs per transport, so a future door costs ~3 lines); +5 misc. Shrink before the final commit: fn-type aliases + slot tables generated from one declarative list, guard boilerplate folded, est -250..-350, re-pinned DOWN in the same commit; the coverage witness must still compare against the linked TRAIT (non-tautological).
- 2026-09-27 ARCHITECT (CI 36320150019 verdict): red on (1) seal-witness false match from auth-admin-tokens' str::bytes (fixed by WARDEN 96e0c940c) and (2) the plugins.yaml registry missing auth-admin-tokens (EXT-AUTHADMIN, urgent). Expensive tiers skipped behind the preflight. Registry gate coverage gap (kinds store|auth|hook|secret only; export/transport/plane repos unregistered) -> WARDEN, widening coverage.
- 2026-09-27 ARCHITECT (per-transport both-ways proofs): NO new loader ledger rows. Spec #2: a plugin tests ITSELF. Each transport's both-ways conformance lives in its OWN crate's tests (links itself + dlopens its own dropped-in cdylib, RED arm kept), the same shape as GetBusbar/transport-tcp; it travels with the crate on extraction. plugin-loader keeps exactly ONE kind-level both-ways witness per kind (transport: tcp now, the pinned-repo dev-dep after extraction). Same rule for every kind going forward.
- 2026-09-27 ARCHITECT (in-crate conformance host): each plugin crate's own tests/conformance.rs drives its dropped-in cdylib through the REAL busbar-plugin-loader (spec #2: same loading path), never a hand-written test host. Grant (kind-neutral): plugin crate -> busbar-plugin-loader allowed ONLY as a [dev-dependencies] edge whose sole user is its own tests/conformance.rs; RED plants for a normal dep and for any other test user. Mirrors the external plugin repos and DOOR-STORE's reverse grant. CI re-dispatched: run 36321398158 at b86e2b685 (registry now covers all 7 kinds).
- 2026-09-27 ARCHITECT (EXT-AUTHADMIN queue): (a) `auth` joins PENDING_KINDS in the kind-isolation gate on the same terms as `secret` (its instances now live in their own repos). (b) Plugin repo layout: logic crate + plugin crate (the door lives only on the plugin crate), recorded as the standard for every extracted plugin — a cdylib on the logic crate double-builds under hash-differing names and the loader can pick the doorless one. (c) NEW DEFECT: busbar-kernel still depends on busbar-auth-admin-tokens and keeps an admin-tokens match arm in core (#40 violation) -> new slot AUTH-ROW: the admin module resolves through the auth kind registry, the root holds the linked row, and the kernel names no auth instance.
- 2026-09-27 ARCHITECT (HOTDOOR-B queue 2 report): inline HOT dispatch is ACCEPTED (765b2ddc9; crossing p50 125-166 ns; the hop cost 2.7-7.8 µs p50). Two corrections:
  (1) STREAMING SAFETY: inline dispatch buffers a streamed body until dispatch returns, so a streaming plane that forgets DISPATCH_BLOCKS silently loses live streaming (first byte late). The default must be safe: the loader refuses at load a plane whose declared answer shapes include a live/streamed answer (the PlaneAnswer::Live path) without DISPATCH_BLOCKS — refusal text names the plane key and the missing bit; if the decl carries no answer-shape declaration, append one at the end of PlaneDecl. Test: a live-answering plane without the bit is refused (RED arm); with the bit, its first streamed byte reaches the caller before dispatch returns.
  (2) The use-collapse drain (carrier types named through an existing loader import line) and the deleted comment clause are matcher dodges, contrary to the standing no-dodge rule — revert both. The residual busbar×plugin-tooling rise from G2 is genuine composition-root -> loader reach (the root is the one place allowed to compose through the loader). It is queued as owner Q81 (re-arm at the measured value, with that reason) — never raised without the owner (§9.2).
- plane-abi-neutrality RED at HEAD: ServerError / handshake_max_rounds in contract hot/transport.rs (78c45eacd) -> DOOR-TRANSPORT drains.
- 2026-09-27 ARCHITECT (HEAD-REDS): test-half [[dep]] busbar -> busbar-transport-tcp CONFIRMED (composition-root allowance). Boot-deadline tests exec the binary once (warm-up) before starting the boot clock — a premise fix (the deadline measures busbar's boot, not OS page-in), not a timeout widening.
- 2026-09-27 ARCHITECT (neutral names, CI 36321398158's one blocker): WireStatusClass {Success, ClientError, ServerError, Other} -> {Success, CallerFault, FarEndFault, Other} (same bytes 1..4; the linked enum and any settlement/FeeEvidence use renamed identically, fee parity unchanged); handshake_max_rounds -> handshake_max_steps. Protocol role nouns (server/client/round) never name an ABI item.
- 2026-09-27 ARCHITECT (CRED-STRIP report): ACCEPTED (cf9f635e8, d45b1423d; oracle 0 DIFF vs base). Tightening: strip EVERY header the configured auth modules read as a credential carrier, whether or not this request's gate consumed it (a second, unconsumed x-api-key beside a Bearer is still a credential and must not reach a plane; zero trust #65). Upstream bytes stay oracle-identical. -> CRED-STRIP follow-up.
- Pre-existing reds routed: the busbar-kernel bench plane_host_vtable_perf.rs doesn't compile (poll_close removed by 78c45eacd) -> DOOR-TRANSPORT; a2a + mcp 5 hook_gate/hook_tap failures each -> WARDEN root-cause (coordinate with DOOR-HOOK); oracle vs the 1.5.5 golden: 24 Q40 busbar_lane_state cells (owner-signed Q40 change — must be in accepted-differences citing Q40; add them if missing, since that records an owner signature, not a new blessing) + 2 crosscut traps (root-cause) -> WARDEN.
- 2026-09-27 ARCHITECT (oracle premise): a filtered oracle diff/replay auto-includes the premise cells of every accepted-difference it may apply, or refuses naming the missing premise; a filtered run never reports an owner-signed difference as a FAIL. The Q40 entry exists (accepted-differences.json:1520); CRED-STRIP's 26 'fails' were a filter that left out ops.scrape|metrics|key. -> WARDEN.
- 2026-09-27 ARCHITECT (SD-8 final): kernel ceiling re-armed at the MEASURED value, 54801 — ACCEPTED; the 63 K2g reserve lines consumed by unruled work are NOT silently re-granted (the reservation entry stands and stays owed). The six busbar-llm-codec SSE tests deleted as duplicates of a2a's -> WARDEN spot-checks they are byte-for-byte the same assertions (else restore them). Flakes under load (export_scrape_is_first_party, the metrics gauge-limit test, one a2a config test) -> WARDEN. Crate count at origin/predev: 35.
- 2026-09-27 ARCHITECT (HOTDOOR-B corrections): ACCEPTED c8400fb00 — the live-answer carriers in provided_carriers are the answer-shape declaration; no ABI append needed. Q81 updated to 191 (+ busbar×plane +1).
- 2026-09-27 ARCHITECT (EX-DEL): ACCEPTED. The third-party own-metric proof is re-homed on a REAL plugin of any kind (#85's fold is kind-uniform), with no fixture; if no real plugin reports its own metric -> architect decides. Third-party traces are covered by traces_stream_both_doors + the policy tests.
- 2026-09-27 ARCHITECT: neutral names landed (32e474caa; plane-abi-neutrality green; settlement_table 24/24). CI re-dispatched. xtask compile-time repo-root (CARGO_MANIFEST_DIR) -> runtime root resolution, or refuse on mismatch (it poisoned a base-vs-candidate gate comparison) -> WARDEN.
- 2026-09-27 ARCHITECT (transport CLAIMS): option (A). Every transport entry carries a CLAIMS list (tcp/stdio/ws one claim each; http: http, sse, grpc). A claim = (key/scheme, session, session_bound, unit0, status_at, status_namespace, facts, selector forms); COMPOSES_OVER stays entry-level (the role); intra-plugin layering between claims is internal and never a row edge. The root registers one row per claim -> one entry; a duplicate claim across plugins fails boot. open() receives the resolved claim. ABI: one minor + a claims coverage witness; contract re-arm in its own commit. MONEY: fee status leg per claim, alone, with a per-claim linked-vs-dropped parity test (http FirstFrame, grpc Terminal; RED: grpc settled as FirstFrame diverges).
- 2026-09-27 ARCHITECT: STORE-DEFAULT accepted (20fbf4c83). The admin catalog 'memory' literal (core-admin service_operations.rs:594/840) reads the linked rows instead -> STORE-DEFAULT follow-up; migrate.rs:935 is 1.5.5 value migration (data) and stays. PRIORITY: 216 cells vs golden/1.5.5 in config|boot|governance|plugins|cli at base -> WARDEN classifies (owner-signed / premise artifact / REAL drift) and fixes real drift at the root.
- 2026-09-27 ARCHITECT (EX-DEL gap a): hook metrics render on /metrics/hooks labelled hook=<instance> — that IS the 1.5.5 behaviour, and #85 names the hook scrape fold as its model; hooks are a functional fixed point (owner), so no change. busbar_* refusal witness = kernel scrape_tests::busbar_prefix_is_reserved (accepted). The +1 busbar×plugin-tooling from 153ddc9d4 folds into Q81's measured figure.
- 2026-09-27 OWNER (plugin fleet design, AskUserQuestion x4):
  (1) LAYOUT: one repo per plugin stays; fix the drift at its root: shared reusable workflows, automated pin bump, and a fleet sync/check.
  (2) VERSIONING: each plugin has its own semver and declares a contract-ABI range; core refuses to load one outside its range; the default distribution pins exact plugin versions.
  (3) CORE->PLUGINS: core's `consumers` early-warning job stays until the 1.6.0 ABI freeze, then it is deleted; after that plugins test themselves against core's published conformance harness and core tests only its contract suite.
  (4) PROMOTION: every plugin repo has dev/qa/main with identical protection and promotes independently; the core release step requires each default-distribution-pinned plugin's qa to be green against the core being released.
  (5) NAMING: every plugin repo is renamed to busbar-<kind>-<name> NOW (repo = crate = artifact prefix); GitHub redirects the old names; the registry gate pattern becomes ^busbar-(store|secret|auth|hook|export|plane|transport)-.
  -> slot FLEET builds it.

### 2026-09-27 — Q81 (busbar × plugin-tooling 168→191): owner REFUSES the raise
Owner ruling: core should load plugins in 1–2 places (~20 mentions), in a boot sequence (read config > load plugins > register > serve), like the teller loop.
The limit is NOT raised. A design analysis (BOOT-LOOP) is running; I will rule the design from its report and dispatch one implementer.
No new busbar→loader mentions until then: slots touching crates/busbar must hold this cell flat.

### 2026-09-27 — KIND-DESIGN (owner directive)
One read-only design agent per kind (store, secret, auth, hook, export, plane, transport) analyzes all the plugins of its kind together. Siblings, not cousins: one template per kind, drift vs essential difference, the core-side footprint and whether the sprawl is needed, and a migration plan.
The brief is in busbar-run/kind-design-brief.md. BOOT-LOOP covers the busbar × plugin-loader cell.
I rule each design from its report and then dispatch implementers.

### 2026-09-27 — BOOT-LOOP ruled (see Appendix D)
The busbar × plugin-tooling cell drains from 190 to ~12 via a single root/boot.rs pipeline, contract-owned host-side types, and one test fixture. Q81 is closed as "drained, not re-armed".
R2: a type re-point is legitimate only if the same commit deletes the loader shims. R3: fetch order and boot lines stay unchanged.
Steps 1–5 are dispatched now (BOOT-LOOP implementer). Steps 6–11 are gated on the plane/transport KIND-DESIGN rulings and on the STORE-DEFAULT/AUTH-ROW landings.

### 2026-09-27 — OWNER: kernel knows nothing of transport; TRANSPORT-CONNECTOR
This supersedes HTTP-FRAMER (a) as to WHERE things live.
- The kernel provides only transport-agnostic bricks. A plane asks for (transport X, details); the kernel instantiates that transport per request.
- The chain is kernel → transport-connector → transport plugins. The transport-connector is a cleanliness crate like admin and oauth2.
- The connector owns: TLS per transport, keys and secrets, pooling, ALPN, and the transport-specific customer settings.
- The transport KIND-DESIGN agent was stopped and replaced by the TRANSPORT-CONNECTOR design agent.
- DOOR-TRANSPORT is on HOLD for: the clock seam, the http framer, the final Connection commit, and the tcp deletion. The ws, claims (A) and SHRINK work may land.

### 2026-09-27 — OWNER: SYNTHESIS
When all the designs have returned (boot-loop plus store, secret, auth, hook, export, plane, transport-connector), save each to busbar-run/kind-designs/. Then ONE synthesis agent finds the similarities across them and designs the FULL scope of kernel <> plugins plus the cleanliness crates. I rule that synthesis design; implementation follows it.

### 2026-09-27 — OWNER: adversarial convergence before sign-off
The synthesis design is attacked adversarially until everyone agrees on ONE design, and then it goes to the owner for approval. Nothing is implemented from it before that.
Process:
- (1) The synthesis agent drafts kernel<>plugins+cleanliness v1 from the 8 designs.
- (2) Parallel attackers, each attacking v1 and returning BLOCKING / NON-BLOCKING objections with file:line or spec-row evidence:
  - each kind's design author, defending its kind;
  - a spec-law attacker (Part 1 Laws, #2 #3 #30 #36 #40 #65);
  - a money/parity attacker (fee paths, 1.5.5 oracle cells, the boot lines);
  - a perf attacker (#30 <1µs crossing, the hot path);
  - a simplicity attacker (fewer crates and seams; sprawl).
- (3) The synthesis agent answers every blocking objection: revise, or refute with evidence.
- (4) Repeat until a round has zero blocking objections, or the unresolved disagreements are crisp and can be put to the owner as choices.
- (5) Present to the owner.

### 2026-09-27 — OWNER LAW: the kernel knows ZERO plugin names
"Red flag any time the kernel knows any plugin names. Should always be 0. The kernel boots and loads the plugins that are in the binary or in the plugin dir. That is how it finds plugins. It never looks for 'x'."
This binds the synthesis and every kind design. There are NO "frozen data" exceptions inside the kernel. The design reports carved out several, and each one is resolved as follows.

Discovery
- Discovery is ONLY by enumerating the linked rows and the plugins/ dir. There are no closed lists of instance names (e.g. EXPORT_MODULES) and no name checks (e.g. the otlp and prometheus singleton checks).
- A per-instance behaviour becomes a fact the plugin declares, such as one_instance, claims_default, reads_settings, or carriers.

Migration, aliases and grammar
- 1.5.x config migration that maps old instance names (the export modules, the redis→valkey store rename, the auth module names) is declared BY THE PLUGIN: legacy names and aliases sit in its row or manifest. The kernel's migrate.rs applies the declared mappings generically and holds no instance literal.
- Pool-strategy words (cheapest, fastest, least_busy, usage) are aliases declared by the ranking plugin, not kernel grammar.
- The secret sugar ({env: X}, {file: Y}) is a shorthand the env and file plugins declare. The kernel resolves it generically.
  - `literal` and `none` are core grammar and are not plugins.
  - `keys` (core's own signed-key verifier) is the badge press and not a plugin. It must still not collide with the plugin vocabulary.
- Refusal texts and --validate lists that name instances are rendered from the rows, byte-identical to 1.5.5.

Tests and cleanliness crates
- Kernel tests use kind-neutral test doubles, never a real plugin's name or crate.
- core-admin and oauth2 follow the same rule.

Allowed and measurement
- The ONLY place a plugin name may appear is the composition root's manifest: the root Cargo.toml dependency, the feature and the linked row. That is data about what is linked, not kernel logic.
- The gate target is kernel/contract/core-admin × every kind instance = 0.
- The instance census must read plugins.yaml aliases and manifest names, so it can see external plugins.

### 2026-09-27 — OWNER LAW: every kind requests I/O from the kernel as planes do (no /metrics in core)
"Export plugins should be like planes: they can request the kernel to load a transport. So prometheus tells the kernel 'I need an https "/metrics" connection'."

This overrules the export design's "/metrics route is core, only the format is the plugin's".

The (transport, auth) need per direction (spec #3: "a plane declares needs as (transport, auth) per direction") is UNIVERSAL: any plugin of any kind that serves or calls over the network declares its needs. Inbound examples: prometheus's /metrics listener, and /metrics/hooks. Outbound examples: otlp, webhook, webrequest, the auth IdP calls, vault.
- The kernel instantiates each need through the transport-connector, per request or listener.
- The kernel owns no route that exists for one plugin: /metrics and /metrics/hooks leave core.
- The data a plugin needs arrives through a kind-neutral host service, for example a metrics snapshot service.
- Customer-visible bytes stay 1.5.5-identical: the path, auth (data key), the 503 boot window, the first-party gate (#65), the content-type and the series.

The synthesis must decide, and the adversarial rounds must attack:
(a) Do plugins with their own wire drivers (the store DB drivers, vault, the ldap socket, reqwest in webrequest and oidc) move onto kernel-provided transports? At minimum: carrier plus connsec/TLS. Their protocol framing stays inside the plugin.
(b) The #63 constraint on webrequest (1.5.5 byte-identical).
(c) The #40 and #65 implications: a plugin that no longer holds sockets or keys.

### 2026-09-27 — OWNER: env and file secrets are ordinary plugins in the default build
env and file become plugins like all the others (busbar-secret-env, busbar-secret-file) and are part of the DEFAULT set linked at build time. A user who doesn't want them builds core + vault and never uses file or env.
- In config, a secret is a secret. The kernel resolves a secret ref by asking the loaded secret rows. The `{env: X}` and `{file: Y}` shorthand is declared by those plugins, not by the kernel.
- A reference to a secret source that isn't loaded refuses boot, with a clear message naming the missing module and taken from the config. The kernel has no knowledge of env or file.
- The default build links env and file, so 1.5.5 behaviour is unchanged.
- Resolution order: secret rows are registered and opened first, because the other kinds' settings resolve through them.
  - env and file declare module_config: none (bootstrap-class).
  - A plugin that needs credentials of its own, such as vault's token, resolves them through a bootstrap-class row, OR the plugin states in its own config how it authenticates. The synthesis must settle this for the core+vault-only build.
- This supersedes the F4 ruling that kept resolve_builtin in plugin-loader.

### 2026-09-27 — OWNER: organizing principle "kernel + plugins everywhere"
This is the spine of the synthesis and the yardstick the attackers use: one name-blind kernel of bricks and services; every capability a plugin, with one pipeline, one row shape and declared needs; cleanliness crates only by justified exception.

### 2026-09-27 — OWNER LAW (generalized): every plugin that needs an external connection asks the kernel to instantiate a transport
This replaces the "every kind requests I/O" wording with the general rule. It applies to ANY plugin of ANY kind that needs an external connection, inbound or outbound: planes, exports, hooks, auth IdP calls, vault, store DB drivers, ldap, and every future plugin. Each one declares the need, and the kernel instantiates the transport through the connector. NO plugin opens its own socket, dials, binds, or does TLS.
This settles open item (a): the own-socket plugins move onto kernel transports. That covers the store DB drivers (postgres, mysql, valkey), ldap, and the reqwest users (webrequest, oidc, github, vault, otlp, webhook).
- A plugin may ask for a raw byte stream (carrier + connsec, no framer), for example a DB wire protocol, whose framing stays inside the plugin. Or it may ask for a framed transport (e.g. http).
- The synthesis must decide:
  - the handle mechanism for COLD-lane plugins;
  - per-plugin feasibility, i.e. whether the driver crate accepts a caller-supplied stream: tokio-postgres connect_raw, mysql_async, redis/valkey, ldap3, reqwest→hyper-over-stream;
  - how 1.5.5 byte parity holds, including #63 webrequest.
  Any driver that genuinely cannot take a supplied stream is an owner question, not a silent exception.

### 2026-09-27 — OWNER: connection needs are kind-agnostic
"Planes and exporters are just plugins needing external transports. Maybe secret will one day: maybe Joe makes a busbar-secret-webservice that needs an outbound connection."
The connection need belongs to the UNIVERSAL plugin declaration, which is the same for all 7 kinds. It is not a per-kind feature and not a plane feature.
- The kernel's instantiate path and the handle mechanism are identical whatever the requester's kind, so a third-party plugin of any kind gets connections with zero kernel or kind-contract change.
- The lane question is answered once, for every plugin: how a COLD-lane plugin holds a byte stream.
- Kind-level witness: prove this with a secret-kind (or any COLD-kind) test plugin that makes an outbound connection through the kernel. The kernel must know neither the kind nor the plugin's name.

### 2026-09-27 — OWNER CONFIRMED ("YES") the kind-agnostic connection model
(1) ONE mechanism for all 7 kinds: the kernel sets up a transport the same way whether a plane, export, store or secret plugin asks.
(2) A third-party plugin of any kind (e.g. busbar-secret-webservice) declares "outbound https to X" and gets it, with ZERO change to the kernel or to its kind contract. The kernel never learns its name or kind.
(3) How a COLD-lane (JSON) plugin holds a live byte stream is answered ONCE, for every plugin.
All three are LOCKED as acceptance criteria for the synthesis and the attack rounds.

### 2026-09-27 — OWNER: "the kernel is just a byte pump: bytes in, bytes out"
The kernel moves opaque bytes between numbered connections and plugins.
What it adds is the governance a pump needs, still without understanding any protocol:
- valves: admission, the egress allow-list, the breaker, budget and the mint ceiling;
- meters: bytes, units and fees;
- the token stamp and auth verify (the badge press);
- the clock.
Everything that understands the bytes lives in a plugin (plane, transport framer, and so on) or in the connector.
This is the headline test for the synthesis and the attackers: any kernel code that parses or understands a protocol, a plugin name, or a plane concept is a BLOCKING defect.

### 2026-09-27 — OWNER TENET: "it's just a dumb busbar"
The kernel is a DUMB busbar. It conducts bytes to whatever is attached and carries the breakers and meters, and it knows nothing about the loads. This is the one-line test for every design decision and every attack objection: does this make the kernel smarter about what's attached? If yes, it's wrong.

### 2026-09-27 — OWNER CLARIFICATION: the pump IS the teller loop
"The kernel is also the teller loop. What you said [numbered connections, opaque bytes, valves, meters, badge press, clock] is true for plugins, but what it pumps bytes THROUGH is the teller loop."
- The kernel's heart is the teller loop: the one ordered sequence every request passes through (admit, verify, scope, budget, dispatch, meter, settle, audit, …; see teller-steps.json and rules.teller-step-order).
- The valves, meters, badge press and clock are STEPS of that loop, and plugins are called from its steps.
- "Byte pump" describes what the kernel sees of plugin traffic: opaque bytes on numbered connections. It does not mean the kernel has no process of its own. The teller loop is kernel-owned, name-blind and protocol-blind.
- The SYNTHESIS §0 and §3 must lead with the teller loop, and place every kernel item as a step of it or a service it uses.

### 2026-09-27 — CORRECTION to BOOT-LOOP R3 and the synthesis Q4 (fetch order)
The premise was wrong. In 1.5.5, fetched plugins ARE seen on first boot: fetch_plugins runs, then plugins_preflight scans in the same boot (v1.5.5 main.rs:2726-2767; predev appbuild.rs:554-605).
So there is no owner question here: 1.5.5 parity requires first-boot visibility for COLD kinds. Q4 is withdrawn.
The design must do fetch through the connector after the connector is up, followed by one incremental load(delta) through the same call. This is an r1 boot-loop objection, handled in v2.

### 2026-09-27 — OWNER LAW: the kernel speaks KINDS, never instances
"The kernel must know planes do x, transports do y, exporters do z. The kernel speaks kinds, so I expect the kernel to have lots of code around kinds, but never about specific plugins."
- Kind-aware kernel code is CORRECT and EXPECTED: per-kind contracts, per-kind registries and views, per-kind host services (planes get governance, transports get the clock, …), and teller steps that call kinds.
- "Dumb busbar" means dumb about the LOADS (instances, protocols, dialects), not about the kinds of socket on the panel.
- Measurement consequence:
  - The kernel/contract/cleanliness × <kind INSTANCE> cells must be 0.
  - Kind vocabulary (the words plane, transport, export, store, hook, secret, auth, and each kind's contract types) is legitimately present in the kernel and must not be drained or reworded away.
  - Where a kind-isolation cell counts kind words rather than instance ids, it is measuring the wrong thing, and the gate should be split into kind-word vs instance-id.

### 2026-09-27 — RULING: kind-isolation precision for English-word aliases (WARDEN (ii), narrow)
Aliases that are ordinary English words (streams, decision/decisions) are exempt ONLY as English prose in comments and docs. They still count in identifiers, literals and config-key position.
Non-English instance ids (llm, mcp, a2a, voice, and every plugins.yaml alias) still count everywhere, including prose.
Requirements: RED plants for the key-position and identifier cases, a GREEN plant for the prose case, and a tree-wide lowering in the same commit.
This resolves the busbar × plane +1 from c8400fb00 (linked.rs:586 "which streams.") without rewording.
It follows the owner law: the kernel speaks kinds, and the gate measures instances.

### 2026-09-27 — OWNER RULED Q2: the plane is "decisions"
The owner said "decisions feels right".
- Plane id is `decisions`, crate `busbar-plane-decisions`, feature `plane-decisions`, repo `busbar-plane-decisions`. The config section `decisions:` is unchanged (#47).
- This amends the #39 crate name. It is new in 1.6.0, so there is no 1.5.5 byte constraint.
- Naming standard for planes: a plane is named for its DOMAIN (llm, mcp, a2a, streaming, decisions). The section keys it owns are plural nouns of the things configured (tools, agents, streams, decisions). There is no singular-vs-plural rule on the plane name itself; the domain word wins.
- Side benefit: it removes the ~1,100 false kind-isolation hits on the common word "decision" (RoutingDecision, GateDecision, …).

### 2026-09-27 — OWNER REMINDER: each plane has its config verb (binding on SYNTHESIS v2)
"Each plane has a config verb, don't forget: pools, tools, agents, streams, decisions."
Spec rows that already lock this:
- #47: one top-level section per plane. pools=llm, tools=mcp, agents=a2a, streams=streaming, decisions=decisions. models nests under pools. rate_card and fees are reserved core-owned sub-keys, stripped before the blob crosses the ABI.
- #49: the section name comes from the plane's PlaneMeta::CONFIG_VERB, and the kernel hardcodes none. providers is the GLOBAL transport-config verb. The per-plane targets are models (pools/streams/decisions), servers (tools) and agents (agents).
- #50: the base_url scheme selects the transport plugin.
- Law 7: a plugin is off until its verb is used.

Resolutions for v2:
(a) pools belongs to the llm plane, as its verb (#47). This REJECTS the r1 plane attacker's "pools stays kernel". Tool and agent failover pools live under their own plane's verb, and 1.5.x migration moves them there via declared rewrites.
(b) The governance valves inside a plane section (breaker, on_exhausted, gates/hooks binding, upstream_credentials, affinity, tier, repeatable) are RESERVED CORE-OWNED SUB-KEYS, generalizing #43's rate_card/fees strip. The kernel reads them generically from ANY plane's verb section and strips them before the ABI. The plane gets its domain keys only.
(c) providers remains the global transport-config verb (#49/#50), owned by the transport side (connector plus kernel scheme match). Planes consume projections of it. This re-affirms #50 against v1's three-way split.
(d) Law 7 applies to plugin SELECTION: a Select stage in boot. Only planes whose verb is present load. Bootstrap and default rows (env, file, store-memory) are named owner exceptions.

### 2026-09-27 — OWNER CONFIRMED ("BINGO! YES") the plane config-verb resolutions (a)–(d) above. LOCKED.
- pools belongs to the llm plane. Tool and agent pools move under tools and agents via the 1.5.x rewrite.
- Governance sub-keys in ANY plane section are reserved core-owned: breaker, on_exhausted, gates/hooks binding, upstream_credentials, affinity, tier, repeatable, rate_card and fees. The kernel reads them generically and strips them before the ABI.
- providers stays the global transport-side verb (#49/#50). Planes consume projections of it.
- Law 7 Select stage: a plane loads only if its verb is present. env, file and store-memory are the only default loads without one.

### 2026-09-27 — OWNER: NO SPECIAL PLUGINS; load only what config uses
"If they are not in config, why load them? No special plugins."
This supersedes the "env, file, store-memory load by default" exception in (d).
- Law 7 applies to EVERY plugin, with no exceptions: a plugin loads iff the config uses it.
- A secret reference such as {env: X} or {file: Y}, or `module: env`, IS a use, so env and file load exactly when referenced.
- OPEN (put to the owner): the absent-`store:` case. 1.5.5 configs with no store block boot on the ephemeral memory store.

### 2026-09-27 — OWNER Q-STORE (OPEN, owner undecided): an absent `store:` block
The owner's words: "memory MAY be different in that if you don't specify a store, memory is default. MAYBE. I MAY make that exception; we MAY want to enforce a store config in 1.6.0 to say the store even if it's memory."
The two candidates:
- (A) A default claim: a store row declares "serve when store: is absent". This keeps 1.5.5 behaviour.
- (B) Require an explicit `store:` in config, even for memory. This is a 1.6.0 customer-visible change: a clear boot refusal, with `busbar migrate` inserting the block.
v2 MUST design the store selection so that EITHER answer is a one-line data or policy change, not an architecture change. The kernel rule is "exactly one store resolves". Whether an absent block resolves through a declared default claim or refuses is one switch.
This stays in the owner-question list and is not decided by the synthesis.

### 2026-09-27 — OWNER RULED Q-STORE = (B): 1.6.0 REQUIRES an explicit `store:` block, even for memory
This is signed by the owner as a customer-visible change vs 1.5.5, with its reason: no special plugins, and config says what loads.
- Boot with no `store:` block refuses with a clear message. The message tells the operator to add a store, e.g. `store: {module: memory}`, and to run `busbar migrate`.
- `busbar migrate` inserts `store: {module: memory}` into a config that has none, which is exactly 1.5.5's implicit behaviour made explicit.
- The declared "default store" claim (STORE-DEFAULT 20fbf4c83 claims_default, and `default_store` in linked.rs) becomes OBSOLETE and is deleted. The kernel rule is "exactly one store resolves, from config".
- Follow-through owed:
  - a CHANGELOG entry;
  - oracle accepted-difference entries for every cell whose config lacks `store:`, citing this ruling. The owner approved the change, so these entries are authorized; list them for review;
  - test fixtures and example configs gain an explicit store block;
  - the migration corpus gets a no-store fixture;
  - the docs.

### 2026-09-27 — OWNER MONEY MODEL (confirmed; matches #77)
- Planes report WHAT UNITS WERE DONE, e.g. `output_tokens = 1`. The kernel WRITES that to the ledger as reported ("what the plane says it did, it did").
- SEPARATELY, money and spend are computed by reading the ledger and applying the associated rate card. This is a generic read-time conversion (#77(3)); price is never stored.
- The kernel does NO plane-specific math.
- A plane billing wrong (e.g. a2a) is that PLUGIN's bug, not the kernel's. The only kernel duty is to give planes all the data needed to count honestly. Every byte in and out flows through the plane, so the plane has no excuse.

Consequences for v2:
- The ONE fee/unit decider is the PLANE's report (money-B1). The kernel's FeeEvidence/settlement must not be a second decider.
- The a2a bytes class is counted by the plane (money-B2). Connection meters are telemetry only.
- The kernel's generic duties: one sealed facts line per unit (#77(2)); budget holds and read-time valuation are generic unit×rate conversions keyed by (principal, meter_class, lane); an unpriced class refuses boot.
- Price at routing time (`cheapest`) is a generic rate-card lookup by opaque lane key. It is not plane math and not a plane-held price.

### 2026-09-27 — OWNER: planes report unit usage AS IT HAPPENS, streaming or not
- Running unit reports go to the kernel during the unit. The kernel checks them against the hold (on_exhaustion finish-unit or cut-stream) and writes ONE sealed facts line at the end (#77(2)).
- Budget placement, per my analysis to the owner:
  - Keep the 1.5.5 placement. The gate at arrival/admit refuses an already-exhausted budget.
  - The HOLD is sized at ADMIT, the first step where both numbers exist: the plane's expected units (from decode, units only) × the most expensive price among the destinations verify allowed (the generic rate card).
  - The hold is accounting, not a second door. It tops up, never refuses what admit allowed, and covers failover without re-pricing (busbar-kernel-budget/src/estimate.rs:1-15, lib.rs:33-42).
  - Route is too late to be the gate; meter is after the money is spent.

### CORRECTION TO SYNTHESIS-v2 (it predates the owner money model message)
v2 step 20 "ONE-FEE: kernel settlement decides; delete the Report.fee_count path" is BACKWARDS against the owner money model.
- The ONE decider is the PLANE's report (units, and whether a fee unit was incurred).
- The kernel's FeeEvidence/settlement fee_count must NOT decide. The transport claim status becomes evidence handed to the plane.
- v3 must invert step 20 and §3.1's meter row accordingly.

### 2026-09-27 — OWNER: no kernel floor for under-reporting planes
"A third-party plane reporting zero is a plane issue. The admin chose a crappy third-party plane; that's on them. Not a kernel issue."
The kernel records what the plane reports. There is NO kernel-side minimum-charge or fail-closed-on-no-usage floor. Plugin trust (signing and first-party policy) is the operator's choice.

### 2026-09-27 — ARCHITECT RULINGS from round 2 (going into v3)
- R2-A The typed linked COLD path (ColdTyped) is DELETED (simplicity B-C, speclaw N-B2). Linked COLD rows dispatch through the same ColdEntry boundary INLINE on the caller: no spawn_blocking and no semaphore unless the row carries the `blocks` mark. This follows the HOTDOOR-B inline-dispatch precedent. It is gated on the C3 decide bench (p99 < 100µs). If JSON alone fails that bench, it goes to the OWNER as a #30 question. It never becomes a silent second path.
- R2-B Running unit reports ride the RETURN VALUE of the host→plane push dispatch, adding zero plane→host crossings (speclaw N-B1). A witness counts plane→host calls per chunk at 0. §9.7-#30 gets a clause for this.
- R2-C Duplicate declarations are derived, not declared: section, path and scheme marks come from sections.owns, the inbound needs and the transport claims (simplicity B-A). `deliver` is derived from the lane. Every `retired` rewrite lives in the root legacy table; Statements carry `live` rewrites only.
- R2-D The collector and loopback-sidecar egress classes are merged into one.
- R2-E ConnId slab entries carry the owning instance and NeedId, and every op checks them (speclaw N-B4). RED arm: a cross-instance id is refused.
- Book stage and store are BOOT-ONLY. Reload never reopens the store, and a changed store: is restart-to-apply exactly as in 1.5.5 (store R2-2, bootloop 2). Selection is per generation over the discovered image set (bootloop 3). --validate includes the section-validate half (bootloop 4). Fetch runs before network secrets, and the delta is admitted (bootloop 1).
- The hook cost recipe is plane-declared data, route_cost [(class, weight)] (hook N2). admin-tokens is a live name, not a retired one (hook N3). hook.call is completion-style (hook N1).
- The valkey port uses sync redis ConnectionLike over the blocking pull adapter, with no aio (store R2-1).
- OPEN FOR OWNER: the h2 credential splice (auth R2-2 and simplicity B-B both found that hyper/h2 always Huffman-encodes, so a same-length placeholder is impossible).
- R2-A refined (perf N2): inline linked COLD dispatch applies ONLY to rows that declare no needs and no `blocks` mark (CPU-only, e.g. ranking and memory). Any row with a pull need or a `blocks` mark runs off-worker (blocking thread plus a per-row semaphore). RED: in debug builds, a parked read on a data-worker thread panics.
- R2-F (perf N1) ADOPT a resumable HOT plane contract:
  - dispatch may return Pending;
  - an appended slot on_piece(state, req, borrowed piece, host reply buffer) -> {consumed, Pending};
  - the plane writes into a host-owned buffer, with no emit callback; the running unit report rides this return;
  - llm is not DISPATCH_BLOCKS;
  - a cap.perf cell with 2000 concurrent streams;
  - perf gates on steps 33 and 34, as a same-machine A/B vs published 1.5.5 with p50 ≤ +5%, p99 ≤ +10%, req/s ≥ −5%.
- R2-G (plane r2): ADOPT all six.
  - PoolSpec carries failover, attempt_timeout_ms, base_named, and per-member tier and timeout.
  - Dealt sections carry a position map, so 1.5.5 line and column survive rewrites.
  - Tool and agent pools use a reserved `pools` sub-key inside each plane verb, with a conditional rewrite form. The kernel keys pool, breaker and lane state by (plane key, entry).
  - route.next / route.settle host services give per-attempt encoding.
  - cost_reserve and cost_settle (nanos) are DELETED, replaced by govern_admit(expected_units), meter_report(units) -> Continue|FinishUnit|Cut, and one sealed end. This is the owner money model. Each lands as a $ commit.
  - decisions egress moves to conn in step 33, with the witness re-pinned before step 34.

### 2026-09-27 — OWNER RULED budget modes
Two per-budget settings.
- `admission: exact | estimate`
  - exact: admit refuses only if the budget is already over; no guessing.
  - estimate: the plane reports expected units at decode, units only. At route, the kernel prices them at the CHOSEN member's rate and tries the next member if they don't fit. It is a known guess and may over- or under-shoot.
- `on_exhaustion: finish-unit | cut-stream`
- DEFAULTS: exact + finish-unit (1.5.5 behaviour). The others are operator opt-in.
- Running spend is live (unit reports × rate card), summed per budget bucket across all in-flight units.
- A non-streaming unit cannot be cut mid-flight; it overshoots by at most one request.
- These replace the "hold sized at admit from estimate" idea, which becomes the estimate mode only.

### 2026-09-27 — OWNER: the estimate is rough by design; optimize for the KERNEL, not costing accuracy
"It's an estimate. It will never be right. Do what's best for the kernel."
ARCHITECT RULING (supersedes the route-time pricing in the budget-mode entry above):
- `admission: estimate` is ONE check at ADMIT: the plane's expected units (reported at decode, units only) × the highest price among the destinations verify allowed, compared with the remaining budget. It refuses if it does not fit.
- There is no per-attempt re-check at route and no budget-aware member skipping. The pool walk stays budget-blind.
- This is the existing estimate.rs sizing reused, with no new kernel machinery.
- exact mode, on_exhaustion, and the defaults (exact + finish-unit) are unchanged.

### 2026-09-27 — OWNER AGREED: outbound resolution follows the 1.5.5 provider-entry shape (docs/providers "what a provider entry is")
- The plane says "send this request to provider X". It builds the unauthenticated request (method, path, headers, body), which is dialect knowledge.
- TRANSPORT comes from the provider's base_url scheme (#50).
- The AUTH STYLE comes from the dialect default (the protocol: bearer / x-goog-api-key / SigV4), overridable by the provider entry's `auth:` (bearer | api-key | jwt-bearer | oauth-client-credentials, with token_url/scope/subject).
- The KEY comes from config (api_key / api_key_env → secret ref). The plane never sees it.
- No new config is invented; this is the 1.5.5 shape. The v3 segment/placeholder splice design is SUPERSEDED pending the owner's answer on WHO applies the key.

### 2026-09-27 — OWNER MODEL: the kernel instantiates the AUTH OBJECT with the credential and hands it to the TRANSPORT
Owner: "the kernel should instantiate the auth object with the token and pass that object to the transport, so technically the auth plugin and the transport could 'see' the token."
Resolved shape (supersedes the v3 §5.3 segment/placeholder/splice machinery entirely):
- The plane calls send(to: provider X, request). The request is unauthenticated and built by the plane.
- The kernel resolves provider X to a transport (base_url scheme), an auth style (dialect default or `auth:` override) and a credential (secret ref).
- At the need/generation seal, the kernel INSTANTIATES an auth-plugin instance bound to that credential. That opaque AUTH OBJECT goes to the transport along with the request.
- The transport calls auth.decorate(final request head, body hash) at the moment the request is final (SigV4 needs the final form), then encodes and sends through TLS. [SUPERSEDED 2026-09-30 by THE DESIGN §6]
- Trust boundary, stated honestly: the plane NEVER sees the key; the auth plugin HOLDS it; the transport sees it pass through in the decorated headers. Both are operator-trusted plugins (consistent with the owner's "admin chose the plugin, that's on them").
- DELETED from the design: placeholders, splice offsets, the Seg/Derived expression tree, nonce scans, and the h2 HPACK workaround (Q10 is dissolved: hyper encodes real headers, and the bytes are identical to 1.5.5).
- Token-minting styles (jwt-bearer, oauth-cc) are the auth plugin's own business: it mints and refreshes its bearer through its own declared outbound need.

### ARCHITECT RULING — store v3 money slots (2026-09-28). Supersedes STORE-MONEY's stand-in `bb_units` (4×u64 was an agent guess; WRONG model).
Model source: busbar-contract/src/slice.rs — a draw is (bucket, dimension, wanted, epoch); dimension ∈ {NanoUnits, Requests, Concurrency, Class(key)}; a chain draw is all-or-nothing.
- `OpId` = repr(C) [u8;16]: node id (8) + per-node monotonic counter (8), minted by the KERNEL, one per reserve / slice_release / coalesced batch.
- `UnitCell` repr(C) (this IS "fixed bb_units[]"): { bucket: AbiStr, pool: AbiStr (absent = All), dimension: u32 (0 NanoUnits, 1 Requests, 2 Concurrency, 3 Class), _r: u32, class_key: AbiStr (Class only), amount: u64 }.
- `reserve` (request-path, may_pend, DeadlineClass::Call): in { head, op_id, epoch: u64, cells: *const UnitCell, cells_len }. out { head, grants: *const CellGrant{slice_id u64, granted u64 (≤ amount), valid_until_ms u64}, grants_len == cells_len, reason: u32 }. ATOMIC: if any cell grants 0 the store applies NOTHING and answers FAILED, reason 1 Exhausted / 2 StaleEpoch / 3 Unavailable (= SliceError), grants_len 0.
- `slice_release` (request-path exit, may_pend, Call): in { head, op_id, epoch, items: *const {slice_id u64, unspent u64}, len }. The store clamps each to what that slice has left, never returns more than granted. out { head, released: *const u64 (per item) }.
- `add_usage_batch` / `add_metering_batch` / `append_audit_batch` (off-path, may_pend, DeadlineClass::WriteBehind): in { head, op_id, cells in batch order (the tree's unit-map shapes + scale marker, per brief §2) }. Applied in order, atomically per batch.
- DEDUPE (all of the above): the same op_id replayed returns the ORIGINAL out and applies nothing. Durable: survives a store restart. Retention ≥ 24h. The same op_id with a DIFFERENT body → REFUSED + diag `STORE_OPID_CONFLICT`, never applied (ARCHITECT call; owner-visible, see the sign-off list).
- Exhausted-window refusal IS testable: the store holds the window's cap (set via the existing bucket config path); M3-store adds the cap input.
- Tests: store_money_acceptance.rs's `MoneySlots` stand-in is rewritten to these shapes at `v3::bind`; the 10 ignored M4c tests go green there.

### From SANSIO-PG 3d7f001 (store-postgres abi16/sansio-core) — ARCHITECT RULINGS for abi/host/conn (M3)
One HOST CONNECTOR serves every store/auth plugin (pg, mysql, valkey, ldap converge):
- Dial: host owns the endpoint list, DNS multi-address, ordering, connect timeout, keepalive. The plugin can answer `REJECT_ENDPOINT` after handshake (e.g. target_session_attrs mismatch) → the connector tries the next endpoint.
- Streams are FULL-DUPLEX (the plugin may write while a read is pending). Mid-stream `UPGRADE_TLS` (pg SSLRequest, mysql SSLRequest, ldap StartTLS) is one generic service; after upgrade the connector exposes the server cert hash (tls-server-end-point for SCRAM-PLUS).
- Connection ESTABLISHMENT (dial + TLS + auth incl. SCRAM PBKDF2 / RSA) runs on the host's connector lane, never on a request worker. Only established-connection traffic is request-path.
- A store op holds ONE checked-out connection for its whole lifetime (multi-round-trip txns across PENDING), released on READY/FAILED/cancel. Host pool per instance (min/max, ping-on-reuse, reset-on-return = plugin-provided reset op). WriteBehind ops keep their conn across reload (carry-over, never stall retire — M1 ruling).
- Cancel may open a SECOND stream to the same endpoint (pg CancelRequest, mysql KILL QUERY).
- Host services: RNG (nonces, RSA seed), process identity (OS user, pid, program name) at open.
- Plugin-owned, no host service: prepared-statement naming (per-connection counter is sufficient).
- Server notices/warnings → the #85 envelope as Diag severity 0/1 (no new channel).
- store-mysql 0791491: fixtures hold 3 throwaway *.test-only.pem keys; repo has no secret-scan config. If GitHub push protection flags them at M3-store push, LANDER stops and reports — bypass is an owner action.
- M6 CHECKLIST: rename export_door! → export_plugin! once the cold export_plugin! (abi/sdk/mod.rs) is deleted (M3-SDK interim name, abi-v2 §A.1 #2). Also delete abi/cold and abi/hot.
- STORE RULING (window/cap, 2026-09-28): ReserveIn carries window_start (caller names the window; no implicit "latest"). Off-path window_caps slot {op_id, WindowCap{bucket,pool,dimension,class_key,window_start,cap,config_gen}}: upsert per (key,window); higher config_gen wins; equal gen + different cap → REFUSED STORE_CAP_CONFLICT; lower ignored. Reserve on a window with no cap → FAILED reason 4 NoCap. Kernel pushes caps at open/refresh and before the first reserve of each window.
- DRAIN rulings (2026-09-28): item 584 (auth "not cacheable" by name) is SUBSUMED by M3-auth: the auth Statement tail's FACT_CACHEABLE replaces the name check when auth is wired (M3-wire-auth must delete `operator_provider()` name test). Item 598 (VerifiedDestination) lands WITH the host connector / transport wiring (M3-wire-transport; KP steps 18-21) — no new lane-only kind in DestinationFacts. Fleet contract_abi drift (4 stores declare 4 → must be 3; vault 1 → 2; transport-tcp 33 → 1) is fixed per kind at M3 re-pin.
- M6 CHECKLIST: busbar-contract abi/sdk `__door` cold #[no_mangle] fns leak 10 extra exports into EVERY cdylib linking the contract; M3-SDK's symbol test subtracts LEGACY_COLD (M6 marker). At M6 LEGACY_COLD must be EMPTY and every plugin cdylib exports exactly busbar_plugin_door.
- CI TIME: xtask tests/cli.rs (every gate selftest serially) exceeds 1h on a Latchkey xlarge. Parallelise the selftests or shard the job before qa promote; owner: whoever owns CI next (WARDEN).
- STORE RULING v2 (supersedes window part of v1): window_start is PER UnitCell (0 = gauge / never-rolling). window_caps push is ATOMIC (whole push refused on any equal-gen conflict; error names first index). ReserveOut.failed_cell u32 (u32::MAX none) = first ungrantable cell. Cancel dispositions 0 UNKNOWN/1 NOT_APPLIED/2 APPLIED. OpId LE node‖counter.
- HOOK/EXPORT RULINGS (review of M3-SEH): request-path results ALWAYS in host buffers (ptr+cap in the In; written+needed in the Out; one re-call on too-small). Hook body = raw request bytes BLOB_OCTETS zero-copy (owner rule); plugin/SDK parses. SignalEntry = tagged value (U64/I64/F64/STR/BOOL) for byte-identical 1.5.5 JSON. StageView carries the full 1.5.5 HookStageProjection; DecideIn carries HookContext budget. ABI field names neutral (ingress_dialect); the SDK maps to frozen 1.5.5 JSON keys. Apply the SAME host-buffer rule when reviewing store/auth/plane/transport shapes.
- AUTH shapes accepted decisions: short-buffer = one fresh re-call on same ticket, second short = FAULT (apply to ALL kinds); default buffers 16KiB/256 groups/16 fields. OPEN for abi/host: inbound-SigV4 store-read host service + TLS-upgrade host action (with the host connector, M3-PT/M3-wire).

### FLEET ABI VERSIONS (ABI-FIX findings, 2026-09-27)
- Satellite plugins' declared contract_abi must move to M0's numbers when each migrates to the memory ABI (M5):
  the four stores declare 4 (target 3); vault declares 1 (target 2); transport-tcp declares 33 (old minor numbering; target 1).
- M1 loader: a kind version newer than the host's must be REFUSED at load (not only an older one).
  The old airlock newer-minor refusal (item 410; recoverable sha 9294d2a92) was the only guard against pre-resize dev builds.

### RULING: ANSWER VALIDATORS LIVE WITH THE SHAPE (ARCHITECT, 2026-09-27, all kinds)
- Each kind's Out-validation is a PURE fn in abi/<kind>/ beside its shapes: `check_<op>(out, caps) -> Result<(), Fault>`.
  It uses u64 math, has no statics, and ships RED tests, one per rule, each failing if its check is removed. M1's dispatcher calls it;
  no host re-implements it.
- Rules every kind's validators enforce:
  - needed_bytes <= u32::MAX, and every needed_<count> <= that kind's hard max, else FAULT.
  - FAILED with a non-zero needed_* that is <= the given capacity is FAULT, because it wastes the one re-call.
  - An absent span (off == SPAN_ABSENT) must have len == 0.
  - A count > 0 with a NULL pointer is FAULT.
  - A bitfield "exactly one of" with 0 or 2+ bits set is FAULT.
  - A count must be <= its cap, with checked arithmetic.
- Secret-bearing answers are ALWAYS secret on the host side. No plugin-set "sensitive" flag; drop IDENTITY_SENSITIVE.

### STORE v3 MONEY RULINGS (ARCHITECT, 2026-09-27, after the fresh review)
- S1 Replay: a replayed op re-writes its ORIGINAL results (grants, released amounts) into the NEW host buffers, and returns the original out.
- S2 "Same body" = the op's value fields only (epoch, cells/items, amounts, caps, window fields). Host-buffer pointers and capacities are EXCLUDED.
  A same op_id with different value fields → STORE_OPID_CONFLICT.
- S3 Recorded under an op_id: only outcomes that APPLIED a change (READY). FAILED or REFUSED with nothing applied is NOT recorded;
  a retry with the same op_id is evaluated afresh. The short-buffer REFUSED is never recorded.
- S4 The kernel never re-issues an op_id older than OP_ID_RETENTION_SECS. A store treats an unknown op_id as new.
- S5 Partial grant size: pinned to what v1.5.5's in-tree store does, byte-for-byte (cite the 1.5.5 code line).
  Customer-visible behaviour stays 1.5.5. used+amount is checked arithmetic; overflow = Exhausted.
- S6 Validators per the "WITH THE SHAPE" ruling. released[i] <= unspent[i]. cells_len <= u32::MAX-1.

### RULING: SHIP-READY RED IS THE BURN-DOWN METER (ARCHITECT, 2026-09-27)
- ship-ready (kind-isolation-ship: standing kind-isolation debt == 0) stays RED on predev until the plugin program (M3 wire → M6) retires the standing debt.
  That is by design: it is the cut gate, not a predev-green gate, and it sits outside the ci umbrella.
- Nobody weakens it, excuses rows, or chases it as a CI fix. The standing-row count must only FALL; any rise is a stop.
- WARDEN reports the standing count after each CI run as the release progress meter.

### SEH FIX-FORWARD RULINGS (ARCHITECT, 2026-09-27, after the fresh review)
- H1 hook decide/transform: EXACTLY one verb bit (decide: PREFER|ABSTAIN|REJECT|RESTRICT; transform: REWRITE|ABSTAIN|REJECT), else FAULT.
  1.5.5's RoutingDecision/TransformOutcome are enums. No precedence rule. HAS_REJECT_STATUS without REJECT = FAULT.
- H2 A serve headers_out_len above 2*64 = FAULT (the 64-header cap).
- H3 needed != 0 with an outcome other than FAILED = FAULT (every kind's written/needed helper).
- H4 A lease (class iv): READY with material requires lease != 0; no material requires lease == 0. error_kind must be in 0..=5,
  and 0 on READY. This applies to secret resolve and to export/hook status/describe/check/serve bodies.
- H5 Export ScrapeIn.families is the WHOLE snapshot, in the 1.5.5 recorder's render order (kind-then-name, per 6855ef238). Fix the doc.
- H6 One RED test per validator arm, with a distinct message per arm. PASS tests are not counted as RED.

### AUTH HARD MAXIMA (ARCHITECT ratifies, 2026-09-27)
- needed_fields <= 64 (matches the 64-header cap). needed_groups <= 65,536 (a FAULT ceiling, far above any real directory's group membership).

### RULING M-SB: THE SHORT-BUFFER ANSWER IS ONE OUTCOME FOR EVERY KIND (ARCHITECT, 2026-09-27)
- "Your buffer is too small" = outcome FAILED with needed_* > the capacity given, and NOTHING applied.
  The host re-calls ONCE on the same ticket with at least needed_*. A second short answer = FAULT.
- needed_* != 0 with any outcome other than FAILED = FAULT (H3). FAILED with 0 < needed <= the capacity given = FAULT.
- REFUSED never carries needed. That corrects the store text: its "capacity too small → REFUSED" becomes FAILED+needed. Store S3 still holds: a short answer is never recorded under an op_id.
- This rule lives ONCE in abi/mechanism/call.rs docs. Kinds cite it and don't restate it.

### PT HARD MAXIMA (ARCHITECT ratifies, 2026-09-27)
- unit counts <= 64; fields/records/routes/claims <= 1024 each; frame pieces <= 4096; bytes <= u32::MAX.

### PT REVIEW RULINGS (ARCHITECT, 2026-09-27)
- P1 (M-SB addendum, all kinds): the short-buffer re-call must be SIDE-EFFECT-FREE. The plugin checks capacity BEFORE acting ("nothing applied").
  Where it cannot know the size before acting (bind, accept, ...), the host MUST pass cap >= the kind's declared MAX for that result.
  Those ops have NO short-buffer path: an over-cap length there = FAULT (a `within` check, not `needed`). transport listen/accept are such ops.
- P2 transport tickets: a full-duplex connection holds TWO tickets, a read side and a write side, each with at most one op in flight.
  Cancel and resume address exactly one. The doc states it.
- P3 validators: check every list element (claims' facts, status_rows' claim index, DialectAuth.dialect < dialects_len,
  RouteCost.class < billable_classes_len, weight finite and >= 0). Unknown enum/flag values = FAULT, with a distinct message per arm (H6).
- P4 on_piece: more=1 with emitted=0 = FAULT; more=1 with EMIT_DONE = FAULT. A non-READY on_piece gets NO early return that skips
  the unit/record checks.
- P5 SHARED VALIDATOR HELPERS: span/needed/within/listed checks, the common Fault enum and OpContract/contract! move to abi/mechanism/check.rs.
  The PT follow-up creates it. Other kinds converge onto it in their next touch; don't reopen landed sets just for this.

### M-SB REFINEMENT for multi-dimension answers (ARCHITECT, 2026-09-27; supersedes the single-dimension wording)
- An Out with several host-buffer dimensions (bytes + items, bytes + fields, ...): the short answer is FAILED where EVERY needed_* carries
  that dimension's FULL size and AT LEAST ONE needed_* > its cap. A dimension that fits reports its full size (<= its cap), which is legal.
- FAULT if: no needed_* exceeds its cap; any needed_* exceeds its hard max; any needed_* is non-zero on a non-FAILED outcome.
- Single-dimension Outs are unchanged: FAILED with 0 < needed <= cap = FAULT.
- Every kind's multi-dimension validator follows this (store list ops, auth fields/identify, hook/export serve, plane arena+fields).
  RED test: one dimension short with the other fitting = legal FAILED; both fitting = FAULT.

### S1 addendum (store): the capacity check (P1/M-SB) PRECEDES the replay lookup. A replay into a short buffer answers the short FAILED and writes nothing.

### HOST CONNECTOR: ONE DESIGN (ARCHITECT, 2026-09-27)
- The host-connector ABI shape is M3-PT's abi/host/conn/ (connector.rs, the 12-service table). DOOR-TRANSPORT's abi/host/conn.rs edits fold INTO it.
  busbar-core-connector (DOOR-TRANSPORT) is the HOST IMPLEMENTATION of that table. Order: PT lands first, then DOOR-TRANSPORT rebases onto it.
- NO `static`/OnceLock/global in busbar-contract (contract-stateless). The `ARMED` OnceLock + arm()/armed() is REJECTED:
  compiled-in plugins share one contract crate, so a process-global would give every compiled-in plugin the same table and break compiled-in = dropped-in.
  The connection table reaches a plugin ONLY through its open/refresh host tables. The plugin keeps it in its own instance state.
  "No table handed" = ConnError::Unarmed, decided per instance, not per image.
- Q84 metadata-host refusal: a named refusal in busbar-core-connector's endpoint check (a pure fn), with RED tests now (169.254.169.254, fd00:ec2::254,
  metadata.google.internal, and the IPv4-mapped/decimal/octal spellings). It runs before any dial.
- M-SB addendum (all kinds): a short FAILED answer writes NOTHING. Every written_* == 0 whenever any needed_* != 0, else FAULT.

### M1 DISPATCH RULINGS (ARCHITECT, 2026-09-27, after its fresh review)
- An instance never crosses after close. Close is refused while other units are in flight. Start/Resume/Cancel on a closed instance = FAULT, with no crossing.
- Every slice built from plugin-reported lengths is capped/validated BEFORE from_raw_parts. No exception for diagnostics or labels.
- Every crossing, ticketless included, is watched by the watchdog.
- The cancel disposition (UNKNOWN/NOT_APPLIED/APPLIED) is carried to the caller. A FAULT on cancel = FAULT.
- No plugin code (dlclose/unload) runs under a host lock.
- Ticketless short answers: Done.short. Re-call only via an explicit recall(prev) that the dispatcher enforces once. A second short answer = FAULT.
- Kind::check -> Result<(), Fault>, and the fault is logged at warn (plugin, kind, slot; no payload).
- Q84 list, extended (ARCHITECT, 2026-09-28): the whole 169.254.0.0/16 link-local range, fd00:ec2::254, fd00:ec2::23,
  100.100.100.200, 192.0.0.192 and metadata.google.internal, in every spelling. A pure check runs before any dial.

### OWNER RULINGS 2026-09-28 (asked by ARCHITECT, answered by owner)
- D-1 "diagnostic codes" accepted-difference: expected_cells 480 -> 481. Extra cell boot.refusal|BOOT-MCP-01|validate (new 1.6.0 surface, no 1.5.5 golden, in accepted-gaps). Precedent d96e8bc42. Forgives nothing new.
- Refund-across-window: SHIP 1.6.0's behaviour (refund the bucket actually charged). M-1 promoted to kind=breaking with an accepted-difference entry. The fixture, the 1.5.5 recording, and the oracle-engine cell change (busbar-release, incl. its two sha constants) are owner-approved. The engine lands first, then busbar re-pins oracle-rust.pin.
- door-only +56 rows (codec-fold relocation): ACCEPTED as relocated debt; they drain with the legacy engine fold.
- Transport door external deps: a MINIMAL REVIEWED LIST. Only the pure protocol/codec crates each door needs; no async runtime, no logging. ARCHITECT reviews the exact list, and each crate is ledgered.
- LDAP sans-IO vs 1.5.5: SIGNED, all three (fail-closed on a malformed reply or hostless URL instead of a panic; fail-fast on an overrunning nested BER length; a 16 MiB inbound cap). Each is registered as an accepted difference with its reason when the LDAP plugin lands.
- STORE_OPID_CONFLICT: APPROVED. The same op_id with a different body is refused, nothing is applied, and the diagnostic is STORE_OPID_CONFLICT. Registered as a new-surface difference.
- Branch protection: QA ONLY (required CI + train-only pushes). ARCHITECT drafts the settings; the OWNER applies them.
- Legacy engine fold (busbar-llm/-mcp/-a2a/-voice -> planes, W4/W5): MAX PARALLEL, one Opus agent per plane, plan-first, landing serially through LANDER.

### LEGACY FOLD RULINGS (ARCHITECT 2026-09-28, from FOLD-MCP's plan; these apply to ALL four folds)
- F1 (#19 vs §11): #19's "byte-identical LOC move" governs pure MOVES (Phase A). Code that must become sans-IO, contract-only plane code (dropping tokio/axum/reqwest/tracing, speaking arrive/on_piece) is a REWRITE whose identity proof is the ORACLE: wire bytes against the 1.5.5 golden, plus the plane conformance suite, plus the money suites for $ steps. Each rewrite step stays small, and every commit stays green.
- F2 (order): TODO step 34 governs. Folds depend on steps 17, 23, 25 and 33. Fold agents do Phase A now and must NOT build prerequisites themselves (disjoint ownership #27e). The ARCHITECT staffs the prerequisite steps (host tables step 3; plane driver steps 4/23; connector 18/19; http 20; auth outbound 21/22; money chain 13-17) with dedicated agents.
- F3: legacy OperationHandler/codec-registry cells do NOT move into the plane. They die with the registry at step 36.
- F4: a JSON-RPC reader shared by two planes becomes a pure, stateless helper in busbar-contract (outside abi/): no statics, no I/O. No lateral plane edge (Law 2), and no per-plane copy.
- F5: the trust lifecycle (sightings, demotion, reverify) is the KERNEL's. Planes report catalogue hashes, and the kernel judges them through a host service `trust.*` added to abi/host, whose shape is defined with the step-3 host tables.
- F6: argument-embedded URL judging (argguard) is a HOST SERVICE call at the same point as today, so the 1.5.5 refusal timing is preserved (oracle identity).
- F7: the RFC 8707/8693 down-scoping token exchange is the AUTH kind's outbound `exchange()` operation (TODO step 39).
- F8: whole-App tests move to crates/busbar integration tests and the plane conformance suites. Test counts must not fall.
- F9: kind-isolation drain text naming "deleted into busbar-kernel" for the legacy engines is wrong; they fold into their plane crates (§11.11). Correct the row text when the fold's step lands.
- F10 (voice PLANE_KEY): KEEP the registered key "voice". It rides customer-visible bytes: lanes, metering provider, audit kind, admin noun, diagnostics and pool names, and 1.5.5 identity wins. The Cargo feature renames plane-voice -> plane-streaming (#18).
- F11 (two implementations): the SERVED implementation is the base (voice SessionCore, the served twilio). The unserved StreamingPlane SessionPlane and the duplicate twilio merge into it or are deleted, with oracle and conformance proof. Served bytes win.
- F12 (net ratchets): a move that raises the destination plane crate's cells is accepted only if the pair (legacy crate + plane crate) nets DOWN in the same commit. Record the relocation in the commit body (precedent c8c15d222).
- F13 (cancel billing): money bytes follow 1.5.5's four cancel rules (THE DESIGN parity M3). Where the ABI cancel disposition would bill differently, the disposition must express the 1.5.5 outcome. It is never a silent change; bring it to the ARCHITECT if the shape can't express it.
- F14 (attribution): the kernel bills the unit's principal. Plane-specific ids (agent, context, task) live in the plane's own records and are never kernel nouns.
- F15 (plugin process-global state): it moves to per-instance plane state; if it must survive restart, it goes to plane records via the store kind. No statics in a plugin.
- F16 (plane external deps): the same rule as the transport doors, a MINIMAL REVIEWED LIST per plane, approved by the ARCHITECT. tonic/axum/tokio/reqwest/hyper/tracing/log are banned (§11.11).
- F17 (repo extraction): folds stop at in-tree crates/busbar-plane-*. Repo extraction is TODO step 40, a separate slot.
- F18 (plane driver + host services): the kernel-side plane driver (the teller loop driving arrive -> admit -> route -> on_piece -> meter -> audit over the M1 dispatcher) and the missing abi/host services are ARCHITECT-owned design, staffed as their own slots. Folds consume them and don't build them.
- F19 (llm engine): the legacy caller loop (Hop/attempt/pipeline, KILLED in the roster) is retired by the flip-then-delete path (TODO 34/36), proven by oracle families (F1). It doesn't move byte-identically anywhere.
- F20 (unit/* homes): the classification table wins over K2h. admit -> kernel-budget (def 5), meter/usage -> kernel-ledger (def 6), audit -> kernel-audit (def 10), verify/approve -> kernel-scope (def 4), authenticate -> kernel-identity (def 3). FOLD-LLM owns these kernel moves (Wave C C1-C4). No other slot edits busbar-llm unit files while FOLD-LLM holds them.
- F21 (protocol lookup): a plane reading its own DECLS instead of the kernel's proto::registry is an accepted named mechanical change.
- F22 (hook projection): the PLANE supplies the hook StageView projection through a plane op (Part 3 §9). 1.5.5's hook tests land VERBATIM against the new path (#85: if one can't be expressed, the SHAPE is wrong).
- F23 (health probers): they become a kernel-breaker service, driven by a plane-declared probe request that dials through conn.
- F24 (plane tracing/getrandom): the fold rewrite removes `tracing` from plane closures (diagnostics via the #85 envelope) and resolves TODO 591 (sonic-rs -> getrandom -> libc). The plane's fold agent owns it, under the F16 reviewed list.
- F25 (engine tests): before any engine deletion, a per-test coverage map to the kernel-egress, plane-conformance and root suites. No test is retired without an ARCHITECT ruling.
- OWNER 2026-09-28: RECORD a `streams|*` oracle family from the pinned 1.5.5 binary (busbar-release engine change approved), so the streaming plane's fold is oracle-proven.
- F26 (OWNER 2026-09-28, webhook): a plane's webhooks belong to that plane plugin. The plugin is on or off, all or nothing, and the plugin decides what routes it serves via its SERVE op and its own settings. Neither the kernel nor core config has a webhook switch. The llm fold keeps the customer-visible default identical to the 1.5.5 shipped binary: whatever 1.5.5's default build answered on that path is what the plugin answers by default.
- F26 CORRECTION (measured): the OpenAI Responses webhook receiver does NOT exist in v1.5.5. It is new 1.6.0 surface (19f659446 "T3"), gated today by a dev-era cargo feature `busbar-llm/webhook-receiver` (off by default). There's no 1.5.5 behaviour to preserve. Per the owner: it is part of the llm plane plugin, served by the plugin's SERVE op, and the plugin's own settings decide whether it answers. The cargo feature is deleted in the fold. It must be registered as new 1.6.0 surface in accepted-gaps (no golden).

### OWNER RULING 2026-09-28 — Q96 streams proof (supersedes the "record streams family" approval)
Premise corrected: 1.5.5 had no voice/streaming path (golden answers 404; spec rows #23/#45). Nothing to record.
RULING: the streaming fold (busbar-voice -> busbar-plane-streaming) is proven on the streaming CONFORMANCE RIG ONLY
(14-leg battery per spec row #23) + money suites. NO oracle change, NO `golden/1.6.0-pre`, NO streams|* family.
The existing `neutrality|routes|voice-shaped-404` cell stays as is. STREAMS-ORACLE slot closed; Q96 resolved.

### F10 CORRECTED (OWNER 2026-09-28: "voice is a dialect of streaming. streaming is the plugin name")
F10's premise ("1.5.5 identity wins") is false: 1.5.5 had no voice. NEW F10: the plane plugin is `streaming`
everywhere a PLANE is named: PLANE_KEY "streaming", crate busbar-plane-streaming, feature plane-streaming,
lanes/admin noun/pool/diagnostic plane names. "voice" survives ONLY as the name of a DIALECT inside the
streaming plane (dialect id, dialect-level meter/audit labels). No plane-level "voice" identifier remains.

### OWNER RULINGS 2026-09-28 batch 4 — PLANE DRIVER + HOST SERVICES (design: Appendix C; review: DRIVER-REVIEW UNSOUND-with-fixes)
- D1 APPROVED: kernel pushes each routing attempt as an ATTEMPT piece (`FROM_KERNEL`) to on_piece; route.next/route.settle
  host services are STRUCK from §2/§6.1. Owner approved these as edits to the unreleased plane ABI v1 ("appended to v1
  before release, layout golden guards"). ARCHITECT reading vs R9: R9 governs evolution of a SHIPPED layout; until
  1.6.0 ships, v1 is still being defined, so v1 layout edits land with the layout golden regenerated in the same
  commit and no bump. After the 1.6.0 tag R9 applies unchanged (extensions-first, fixed append = bump).
- D2 APPROVED: one HostSlots table (clock, records, dest, sign, unit, work, trust, hook families) on the connector call
  shape. HostTables.conns swaps to ConnectorSlots BEFORE HostSlots is appended.
- D3 APPROVED: kernel owns session money. #28(3) plane-side reserve STRUCK. New kernel session account: per-turn
  CHECKPOINTS only (never ledger lines), ONE sealed line at session end. plane_host/session_meter.rs report_turn
  (writes a ledger line per turn) is NOT reused.
- D4 APPROVED: webhook signature verify = auth-kind inbound verify; replay refusal via claim record; plane never sees
  the secret. Surface is NEW in 1.6.0 (F26 correction) -> accepted-gaps entry, not "bytes preserved". Enablement is
  the plane plugin's own config (F26), not a core switch.
- D5 APPROVED: store v3 put-if-absent-with-TTL slot (tie to IdempotencyKey item 603). Approval redemption = records.claim
  ONLY (trust.redeem struck — one path).
- D6 APPROVED: unit.nest whole buffered reply; one live attempt per unit (no hedging); project once per unit, stage fields
  kernel-filled.
ARCHITECT RULINGS from DRIVER-REVIEW (binding on v2):
- R-A M1 gains an async completion (waker on ReplySlot) — K1 prerequisite; the pump runs on the caller's runtime task,
  never blocks a runtime thread.
- R-B unsolicited output: instance driver ticket `drive` wake -> plane names ready sessions -> driver calls
  on_piece(FROM_KERNEL) per session. No per-session driver ticket.
- R-C cancel: driver keeps its own facts (far-end answered, streamed, last reported units), ALWAYS calls ticketless
  cancel itself before the loop future can drop; cancel FAULT/None bills as CANCEL_FAILED (nothing); hold release
  separate. Nothing crosses the dispatcher inside `abandoned` (Drop).
- R-D budget check may use estimates; BILLING = reported units only; a cut bills what streamed per §7/#77(7) using the
  last reported units. Checkpoints: bounded cadence + a named store slot (TD 15), not a durable write per chunk.
- R-E work continuations are NEW units (own arrival/admission/window); work.resume only binds the record.
- R-F host-service M-SB: ServiceOut extension carries `needed` per dimension; plugins declare max buffer sizes at open
  and preallocate; the PLUGIN re-calls once; a second short = plugin-side FAULT of that op.
- R-G any service that may pend is callable only inside a ticketed op; pure ops (arrive/refusal/project) calling one
  get a refusal; RED test.
- R-H host keeps the caller body and re-pushes it on every ATTEMPT; verb/target are explicit fields.
- R-I no per-plane chain framing list (fixed audit record, §1). records.get has read-your-writes within the instance
  (write-behind batch is consulted on read).
- R-J project writes abi/hook's own RequestView (no restatement in abi/plane); neutral names; no banned tokens.
- R-K carry over entitlement_check, gate_scan (in-session content governance), verify_lookup/verify_store single-flight
  as host services; dest.judge keeps 1.5.5 refusal timing (DNS pend inside a ticketed op); verdict=retry after first
  byte -> treated as hard (no failover after first byte).
- R-L DAG: K1/K2 ARE TD 4/23/24 (no new names — reuse TD numbering); K3 IS TD 13-17's consumer, not a re-do.
  Critical path: M1(landed) -> M1-async -> P1 -> K1 -> {K2->K5, TD13-17->K3, M3-store->K4} -> MCP-1; FOLD-MCP phase A alongside.
  Folds still wait for TD 23 (F2). STRM row: key `streaming`, proof = conformance rig + money suites (Q96).

### OWNER 2026-09-28: HTTP/2 is a DESIGN question (ARCHITECT's), not a rules question.
Settled: h1/h2 framing lives in the http TRANSPORT plugin; host (kernel+connector) keeps OS socket/readiness (io.*), TLS, ALPN, pools.
ARCHITECT criteria for the h2 framing code (either option must meet ALL): no thread, no socket, no runtime, no global
state, no log/tracing leakage, identical compiled-in vs dropped-in, Ready|Pending over host readiness, 1.5.5 parity
(default ALPN h2 to providers, h2c prior-knowledge key, http1-only key, keep-alive 30s/10s, adaptive window).
Preference: the `h2` crate driven as a state machine IF a spike proves it meets the criteria; otherwise in-tree codec. H2-SPIKE (opus) measuring.

### OWNER RULING 2026-09-28 — PLUGIN LIBRARIES (supersedes F16 banned list, the transport "minimal reviewed list", and the §11 plugin-closure-deps tracing/log/tokio denies)
Owner: "http transport plugin uses whatever libs it needs to do its job. we aren't going to cut it off at knees over some silly rules... prebuilt makes most sense."
RULE: a plugin may use whatever third-party libraries it needs (tokio, hyper, h2, tracing, ...). Walls that REMAIN (they are the design, not lib rules):
 (1) a plugin talks to busbar ONLY over the ABI; its busbar-* closure is busbar-contract only (#2/#40a/#84);
 (2) host owns OS sockets+readiness, TLS keys, allow-list/pin/breaker, money; secrets per §6 (#7/#40b).
HTTP/2: USE A PREBUILT LIB (h2 or hyper client-conn) in the http transport, driven over the host-socket shim. H2-SPIKE converts to proving that drive path.
Follow-up: relax plugin-closure-deps gate + spec §11 gate text + F16 accordingly (WARDEN-class slot).

### OWNER 2026-09-28: "building our own is out, that's silly." NO in-tree protocol implementations where a solid prebuilt lib exists: HTTP/2 via h2 (or hyper over h2), HTTP/1 via hyper/httparse, WebSocket via tungstenite family. The earlier "WS framing + HTTP/1 bodies in-tree" plan for the transport doors is VOID.

### ARCHITECT RULING 2026-09-28 — PLUGIN LOGGING (owner: "a plugin-global issue. any plugin that logs, logs where and how")
Governing: #85 (every reply carries {result, metrics[], diagnostics[]}; plugin REPORTS, host VALIDATES/BOUNDS/DECIDES).
ONE PATH for every plugin, every kind, both builds: whatever a plugin (or a library inside it) logs becomes #85 diagnostics
on the reply; the HOST writes it to the host log, tagged with plugin instance + kind, filtered by the host's configured
level, bounded (rate/size) by the host. A plugin never writes to stdout/stderr/files/global logger directly.
Library logs (tracing/log from h2, hyper, ...): the door wrapper in busbar-contract runs every plugin call inside a
per-call SCOPED capture (tracing::dispatcher::with_default + a log-crate shim) that turns events into diagnostics, so
compiled-in and dropped-in produce the SAME host log lines. Witness: same plugin linked + dlopened emits byte-identical
host log lines for the same call (RED arm: a plugin logging via the global logger is caught). Slot: LOG-BRIDGE (opus).

### OWNER 2026-09-28 amends PLUGIN LOGGING: "they should be consistent. all plugins should log to their plugin's log file. no logs for plugins is not an option."
DESTINATION = one log file PER PLUGIN INSTANCE (not the host log). Same capture path (per-call scoped capture -> #85 diagnostics),
the HOST writes each plugin's file (plugins need no fs access; identical compiled-in vs dropped-in). Host config sets the log dir,
level and rotation (same rotation rules as the host log). Silence is not an option: capture is always on. CHANGELOG entry (log location change vs 1.5.5).

### OWNER CORRECTION 2026-09-28: ONLY THE llm PLANE EXISTED IN 1.5.5. mcp, a2a, streaming, decisions are NEW in 1.6.0.
=> 1.5.5 byte-identity (oracle) applies to llm + core surfaces only. For the 4 new planes the baseline for a FOLD/MOVE is current predev behaviour (preserve it; proven by tests + conformance rigs + money suites), and their customer surface is new 1.6.0 surface (accepted-gaps where applicable). Never cite "1.5.5 texts/behaviour" for mcp/a2a/streaming/decisions.

### ARCHITECT rulings 2026-09-28 (late)
- FOLD-LLM C4': option (a). The destination guard goes in busbar_kernel::door, re-armed under R-KERNEL. No kernel->kernel-scope edge; (c) rejected. C3' audit next.
- FOLD-VOICE: READY to LANDER. The A5 F12 relocation is approved (net -3). Voice rows drain. The one amend of an unpushed commit (message only) is noted.
- DECISIONS-JEV: no fee units. Model resolution with zero or several models keeps predev behaviour. The `decisions` section move is approved as an F12 relocation. The jev registry plan is corrected to cover systemone only. Finding 395 is kept.

### 2026-09-28 — accept */* (owner-agreed: the http transport owns client defaults)
DOOR-TRANSPORT landed (predev 9f6e49d55). The door adds accept */* when the caller sets none, plus host and origin-form on h1.
Five kernel egress sites set no Accept where 1.5.5's reqwest added one. All close when their egress moves onto the connector and the http door; no kernel patch:
 1. egress_auth/oauth_client_credentials.rs:124-139. 1.5.5: :119-120 .post().form(). Real regression today. Owner: AUTH-OUT (step 22).
 2. egress_auth/jwt_bearer.rs:183-196. 1.5.5: :177-178. Real regression today. Owner: AUTH-OUT.
 3. auth/token.rs:957-1005 execute_hop. 1.5.5: :915,949. Real regression today. Owner: the auth-kind ports.
 4. preflight.rs:999/1048 plugin_fetch_downloader. 1.5.5: main.rs:2605-2641. Owner: the connector switch.
 5. plane_host/egress.rs:1068. No difference for llm/mcp/a2a, which set their own Accept. Owner: the connector switch.
The C0 agent records the RED cells (1-4 from v1.5.5), marked known-red.
Other rulings:
- ws PIECE_TEXT vocabulary bit (no layout change).
- BOOT-CHAIN statement section: (c), the signed manifest is the no-dlopen source; the object crate is withdrawn.
- K1: invert kernel→loader through a contract handle; no raises.
- lk-cached.sh patched: full context only for gate/oracle/git jobs, depth-1 bundle otherwise (backup .bak-2026-09-28b).
- 2026-09-28: autoscaler 0b0ae25 deployed (multi-region: us-east-1, us-east-2, us-west-2, ca-central-1). Owned infra ensured in each region. verify 19/19 PASS: 0 instances anywhere; a burst would pick us-east-2 (cheapest).
- CONNECTOR-19: HostWire goes in busbar-core-connector (a Transport face row only as an F12 relocation vs the tcp drop). The http proof is option (c): the connector dlopens the http_door cdylib, with no new rows.
- LOG-BRIDGE landed (8e0b147f6). The parallel test flake goes back to its author for a root fix.

### ARCHITECT RULINGS 2026-09-29
- H2 Q1: loader stores Caller{instance,kind} in InstanceWake at bind; HostServices records/sign/trust take &Caller; kernel per-instance fact registry via KernelServices::admit (K1 wires bind call); unregistered = REFUSED.
- H2 Q2: records.claim reuses store v3 slot 31 (put-if-absent+expiry); no store append (D5 satisfied). IdempotencyKey minted sha256(instance||0||kind||0||key) closes 603. ttl==0 refused at validator; checked add.
- H2 Q3: records.get/list via kinds::Store record_get/record_scan (v3 typed), schema = caller's record kind; legacy RecordStore not extended.
- H2 Q4: kernel PendingRecords overlay per instance for read-your-writes; driver batcher fills/drains (K1/K4).
- H2 Q5: trust policy from KERNEL-VALIDATE trust::section TrustEntry map; NEW/SAME/DRIFTED-once/QUARANTINED; clears on re-sight of pinned hash; DemotionRecord durable.
- H2 scope += verify.lookup/store, entitlement.check, content.scan (R-K) as second batch.
- FOLD-MCP phase A plan approved (A3-A7); Q-M1: kernel ingress/jsonrpc pure half -> busbar-contract/src/jsonrpc.rs (F4), kernel re-exports; contract re-arm measured own commit.
- K1 (b) busbar×plugin-tooling 96->97 is predev's own red from c04366ae7; KISO-FIX slot fixes root. No standing move.
- OWNER 2026-09-29: cost-conscious agents — don't stop running ones; going forward fresh agents with short handoffs over long-transcript resumes; cheapest adequate model.
- FOLD-VOICE B/C (4f9031b02..d8a30d7da) READY: F12 relocation plane-streaming×transport 140->141 vs voice×transport 298->288 ACCEPTED (recorded in SLOT-LOG/READY since no amend). Remaining busbar-voice items wait on K6/connector/auth (list in SLOT-LOG row). F16 `url` crate question is moot: owner PLUGIN LIBRARIES ruling allows it.

### OWNER 2026-09-29 money rulings
- #21 keep 1.5.5 (fee on admission count) — closed by-design. #33 fold_v1_ledger wired into migrate (backup-first, idempotent). #34 remove currency from audit digest + recipe version migrate.
- #32 (ARCHITECT, owner didn't follow the question): adjust corrections target whole stored rows; finer ranges refused with clear error; no storage change. Budget door prices per card period via #23's one function. Slot MONEY-WAVE3 (opus).

### OWNER CORRECTION 2026-09-29: "there is no outbound auth plugin. there is an auth plugin that applies auth to connections/transports. the direction is irrelevant."
=> crate busbar-auth-outbound and spec §6 "outbound styles ... one plugin busbar-auth-outbound" wording are wrong framing; rename pending owner name pick; spec §6 wording reconcile.
- FOLD-A2A: plane crates stay forbid(unsafe_code); SDK-SAFE slot (opus) adds safe Blob/AbiStr bytes, typed instance helpers, host-buffer writers, and v1 Claim flags CLAIM_OPEN/CLAIM_EXACT (pre-tag, no bump). Plane settings blob = own section JSON with reserved keys stripped; upstream_credentials is kernel-owned (passthrough -> caller-credential style).
- C0 busbar-release c0/capture-egress-accept pushed @37a53a8.

### OWNER GRANT 2026-09-29 — standing ratchet authority (ARCHITECT), each logged with measured number, never hidden:
 (1) a new crate's first measured cells; (2) F12 relocations where the same lines move and the total nets down; (3) kernel/contract line-limit re-arms at measured value in own commit. Any other real rise -> owner.
- Owner on auth crate name: "why is it not in busbar-auth? why we need anything new?" -> answered; awaiting name.
- MONEY-WAVE3 corrections: #32 = refuse retroactive RATE corrections (amend_rate_history) that cut inside a stored row; adjust untouched. #33 = no engine fold (1.5.5 had no data dir; 1.5.x rows live in store plugins' DBs; legacy adapter dies at M6) -> each store plugin's migrate upgrades its 1.5.x rows, proven by per-backend 1.5.5 golden; delete engine fold_v1_ledger. Budget-crate Door has no production caller -> not polished; K3 picks the one admission path.

### OWNER RULING 2026-09-29: A2A over gRPC is supported in 1.6.0, BOTH directions (inbound ingress + outbound over http transport h2/TLS and h2c). Legacy GrpcTransport deletion still OK (never carried it) but must prove the supported path e2e before/after; gRPC binding reads grpc-status from trailers (1.5.5 trailer-drop applies to llm paths only).

### OWNER DIRECTION 2026-09-29: max compatibility — every plane should support the transports/bindings in its protocol's OFFICIAL design (a2a, mcp, llm dialects, streaming). Research agent building compat-matrix.md; ARCHITECT proposes, owner approves scope.

### OWNER 2026-09-29: "the design of busbar should make grpc a no brainer add and minimal change - 1 new transport and thats basically it"
=> REVERSES ARCHITECT ruling "gRPC is not a transport". gRPC = new transport door busbar-transport-grpc layered on HTTP/2 (like ws on h1). Slot GRPC-DOOR (opus). Acceptance = owner's claim: outside-crate diff ~ root row + workspace + pre-tag vocab only; zero kernel/plane change. a2a claims keep transport "grpc". Legacy in-process GrpcTransport deleted right AFTER the door lands (same series). STEP-20 exposes response trailers to layered transports via a transport-ABI piece; http door caller output still drops trailers (1.5.5).

### 2026-09-29 rulings (cont.)
- TRAILERS: FramePiece PIECE_TRAILERS=16 (once, after last body, before END, exclusive of HAS_CODE/END_OF_FRAME/STREAM_FAILED); EmitIn _reserved->flags, EMIT_KEEP_TRAILERS=1; default drop (1.5.5). STEP-20b implements; GRPC-DOOR consumes.
- WIRE-HOOK Q5: NotifyIn += signals/signals_len, prompt: PromptView, present (VIEW_HAS_PROMPT), _reserved; prompt only under `prompt: ro` grant; byte-exact 1.5.5 notify JSON.
- BOOT-CHAIN: Statement claims = scheme AbiStr list (+ protocols list); root::loader = one pub(crate) mod in busbar root re-exporting plugin-loader items; first to land creates it.
- OWNER Q: OpenAI Realtime (WS/WebRTC/SIP), Gemini Live, Twilio = STREAMING plane dialects (spec #12/#45), not llm. SIP: #45 says raw SIP not carried -> owner decision.
- LANDER4 = a9d3aa98fcff5405e (LANDER3 exited mid C3').
- GRPC-DOOR (L): the connector composes ONE framer per connection, so no framer stacks over another. The grpc door is a framer over the carrier (composes_over tcp), running hyper h2 client/server itself. TRAILERS contract WITHDRAWN. The sans-IO pipe, executor and timer are extracted into a shared lib crate busbar-transport-kit (not a plugin); http switches to it (GRANT 2 relocation). The root row is written against CONNECTOR-19 HostWire, with no legacy Arc<dyn Transport> row. gRPC ingress = a dedicated listener; a missing inbound-listener capability is a kind-generic CONNECTOR gap. The kernel's shared-port tonic service is legacy, deleted along with GrpcTransport.
- GRPC kit home: busbar_contract::abi::sdk::hyper_io behind the optional contract feature "sdk-hyper" (framer plugins only; #40(a) closure stays contract-only). GRANT 2 relocation from http, GRANT 3 contract re-arm.
- INBOUND-LISTEN (kind-generic gap): boot collects DIRECTION_INBOUND needs plus their bind from instance settings; the connector binds one listener per need, then per connection runs framer begin(SIDE_ACCEPT) (+TLS server wrap); pieces go to K1 arrive(unit)/on_piece and replies come back via emit. Connector part now, driver binding after K1.

### OWNER 2026-09-29 compat scope: IN = MCP session-based Streamable HTTP (2025-06-18/2025-11-25), MCP legacy HTTP+SSE (2024-11-05), Bedrock InvokeModel dialect. OUT = native SIP (#45 stands). Owed by spec already: grpc door, Twilio MS transport, A2A push delivery, transport-unix, WebRTC media (#45).

### OWNER 2026-09-29 priority + streaming scope
- PRIORITY: mcp, a2a, llm, decisions >> streaming. Streaming = exactly 3 dialects: OpenAI Realtime (WS + WebRTC, #45 kept), Gemini Live, Twilio. SIP skipped. Streaming work (Twilio MS transport, WebRTC media) staffed AFTER the priority planes' work is in hand.
- Staffed: DECISIONS a695fb131685043d2 (opus, steps 31-33), MCP-COMPAT a2e9e77df96efe0fe (opus), A2A-PUSH a340c0e2dbef2bd5f (sonnet), BEDROCK-INVOKE aa81076003d41ab18 (sonnet), INBOUND-LISTEN a2f8f8bb62e66be46 (opus).
- BEDROCK-INVOKE: Anthropic-on-Bedrock InvokeModel chat only; other families reachable via Converse, so not added. $ usage row lands alone. Code goes where the fold lands the codec.
- A2A-PUSH: retry ≤3 (250/500ms ±20%) on transport/5xx/429 only; async timer; no slot held; SSRF judge re-run per attempt.
- MCP-COMPAT approved: sessions CSPRNG ≥128 bits and bound to principal+tenant (RED); negotiation only (no revision config); per-process sessions; the 2026 stateless path byte-identical; line growth recorded under the owner scope ruling (report to owner); cross-kind or kernel/contract rise = STOP.
- DECISIONS: KFEAT = binary feature plane-decisions is the one switch. Step 32 route.* superseded by §11.12; route.failover/BOOT-P33/34/36 belong to the llm route seam. Pools-under-verbs (#47) is a separate slot (POOLS-VERBS, unstaffed). Production FarEnd/MoneySeam = K2 (staff right after K1); D5 waits for them.
- A2A-PUSH: streaming sink delivery detached via a per-task ordered bounded queue (64, drop-oldest + metric); no stall of the chunk pump.
- INBOUND-LISTEN Q1: inbound need target_from -> settings block {listen, tls{cert,key,client_ca?}} (1.5.5 shape, secret refs); ALPN from framer offer; no ABI append; max_conns default 1024 (CHANGELOG); address clash refused at validate. C3 stacks on boot-chain.
- OWNER 2026-09-29: decisions plane should be like llm: N dialects + IR for cross-compat. Candidates: jev (have), laya (NandhaKishorM/laya), kev (jaredpalmer/kev), von (wfzyx/von). Research -> decisions-dialects.md, then design ruling.
- WIRE-STORE Q8: (b). Contract StoreOpener seam implemented by the root over the ONE Dispatcher plus the registry, installed via RootRows; appbuild calls the opener; kernel stops naming loader. The registry build moves to root (coord BOOT-CHAIN). kernel×plugin-tooling may only fall. Applies to every kind's open path (secret/auth/hook/export same pattern).
- Opener seam naming: <Kind>Axis in contract (template = ExportAxis: probe/check/open(module,label,settings) -> Arc<dyn <Kind>Calls>), impl in root over ONE Dispatcher + registry, installed via RootRows. Supersedes 'StoreOpener'.

### OWNER 2026-09-29 decisions plane = N dialects + IR (like llm)
- Research: jev/laya/kev/von are dialects of ONE protocol (POST /v1/systemone spine). Dialects: jev, laya, kev, von; #51 selection, fail-closed. Ingress = shared spine + GET /v1/models. Same-dialect = byte passthrough; IR only across dialects (state opaque, questions, answers, confidence{value,formula-id}, correlation_id, error via error_map, usage{decision_units,input_tokens,output_tokens}); untranslatable -> named refusal. Meter class stays "decision"; the decisions rate_card prices per_decision + input/output token rates ($, alone). Assigned DECISIONS agent as D6 (IR) D7 (codecs) D8 (models) D9 ($ tokens).
- CORRECTION (owner: "dialects or providers?"): laya/kev/von are PROVIDERS of the one systemone dialect (like groq/z.ai for the openai dialect, #51). No 4-dialect IR. Per-provider error_map and usage pointers are catalog data; bytes pass through. A second dialect only if a provider's request spine really differs. D6 = 4 catalog providers + tests; D8 models; D9 $ token pricing.
- 2026-09-30: need.protocol/LocateIn.protocol (STEP-20 G3, ruling 388) WITHDRAWN: no consumer since grpc is its own framer. The Statement claims stay scheme strings only. RESUME wave after the session-limit outage: all slots re-spawned fresh (resume.md). LANDER5 = aa0945fd7f1d4c592.
- DECISIONS Q1-5: D2 = decisions capability-equality column (GRANT 1, argued cells, ARCHITECT reviews); usage pointers are DIALECT data (/usage/units,/usage/input_tokens,/usage/output_tokens), catalog = error_map only; protocol `jev` for all providers (typesafe base_url + self-hosted templates); /v1/models = kernel appends each plane generation's listed names (bytes unchanged if none); billable classes decision+input_tokens+output_tokens family "decision", all three required (0=free) ($).
- OWNER 2026-09-30: unlimited tokens; staff everything now. New slots: K2 a9d6acf5b3b80f9f7, POOLS-VERBS a80fddd12b33084b2, BEDROCK-INVOKE a57fabcc05f564d1c, METER-FIX a606bbbd3592d80e4, AUTOBAHN a5a2f82e09bbf0a06.
- DECISIONS scope (jev101 list, 30 engines): 22 PROVIDERS as catalog rows (path overrides via #51 path/path_base); NanoJev = 2nd dialect 'nanojev' (cross-dialect = validate refusal unless exact translation); Fastino pending its schema research; 6 N/A. Card prices decision+input+output tokens (0 = free); document per row what output_tokens counts.
- BEDROCK-INVOKE: ModelCfg += protocol + error_map overrides (#51 exact), fail-closed; bedrock-invoke = MODEL-ONLY protocol (ProtocolDecl.model_only): not a valid provider default, excluded from the must-be-one-of list, telemetry index appended after the 1.5.5 families; the $ DIALECTS row lands alone. DECISIONS reads the same ModelCfg.protocol.
- POOLS-VERBS approved: pools lifted per plane section (#43/#47), root pools llm-only (1.5.5), pool names globally unique, pools under decisions/streams = validate refusal, migrator moves plus a visible TODO report.
- TRANSPORT-UNIX approved: claim 'unix', unix:///abs/path only, SelectorForm Path, connector socket enum on connector-19 (lands after it), unlink only if S_ISSOCK, refuse symlinked parents; connector ceiling rise reported before re-arm.
- TWILIO: streaming dialect over ws (no transport crate, §9 lists 5). Claim restored on WS_TRANSPORT PrefixOneLevel('/twilio'). Inbound auth = new mechanism-named auth plugin busbar-auth-webhook-signature (variant twilio: HMAC-SHA1 X-Twilio-Signature), scheme alt 'webhook-signature'. Slot TWILIO-DOOR a48d89c1777a33583.
- Fastino: llm catalog provider (openai dialect), not decisions. NanoJev is the only 2nd decisions dialect. AnyJev/Decitron N/A.
- WIRE-AUTH: AuthCalls::verify_now (ticketless, watchdog-bounded) + the admin Authenticate step made ASYNC (submit+await on pending; no 503 for pending I/O). SUPERSEDES 'poll once Pending->503'. Axis install via the existing root->kernel door, named install_<kind>_axis.
- WEBRTC: mimic HTTPS layering (owner framing). udp carrier = host; DTLS in CORE/connector like TLS (host cert, RFC 7983 demux); webrtc framer = ICE+SRTP+SCTP and gets the exported SRTP keys via one narrow ABI item; plugin holds no DTLS state. Approved: busbar-minted tickets, Opus C dep, admission at SDP accept ($). Redesign pending from WEBRTC a149032d754939a06.
- OWNER 2026-09-30: transport encryption = ONE core-owned secure-layer slot in connector compose (carrier -> [secure layer] -> framer) with SIBLING engines: tls (stream), dtls (datagram), future XYZ. Same flow: host owns keys; framer gets plaintext + optional keying_material exporter via one generic ABI item. Existing TLS refactored as the first engine, byte-identical.
- WEBRTC redesign approved in shape (demux, ICE-gated bind, core DTLS, contract items 1-4, §5 row: the framer holds SRTP keys). DTLS MUST run on ring (no second crypto backend); prefer dimpl + ring adapter; it shares ring/pki-types/rcgen with TLS. C0 spike reports the exact crate diff before C1.
- OWNER 2026-09-30: keep bloat in check. Every READY adding deps carries a cargo tree diff; the LANDER bounces unexplained Cargo.lock growth; ring only; C deps need ARCHITECT approval.
- OWNER 2026-09-30: no rustls-for-this/blahtls-for-that. One library per protocol, one crypto backend (ring). No pure-Rust lib does TLS+DTLS; the least-bloat choice is rustls (TLS) + dimpl (DTLS), both on ring, sharing pki-types/rcgen and the core secure-layer slot.
- WEBRTC v3 APPROVED (ARCHITECT, unattended): SecureEngine seam in the connector (tls engine = today's rustls code moved, byte-identical); dtls engine with RFC 7983 demux + cookie + ICE-gated associations; contract: keying_material exporter, datagram ingest/send with clear|secured class, local_cert_fingerprint, Datagram class/udp/webrtc roster, rendezvous open; rebind_path for ICE migration (RED on spoof); SRTP profile AEAD_AES_128_GCM ONLY (ring); rtc-* modular crates if str0m needs a fork. C1 after connector-19 + inbound-listen land.
- Staffed (unattended): KV-FIX ab0bb9c4910679bb1, TODO-RECONCILE aa80dc147b0c975df, FOLD-LLM2 a97e30f605e733203, K5 a0f287ad5ef15f17b, K6 a1866fd89e1211d8e, H3 a6e89675a94375aa4, MONEY-CHAIN a7bad5c54a72e2e77, WARDEN a1d4ae60b29e9f91b.
- MONEY-CHAIN approved C1-C9 (TD13-17 + K3): ledger row-count change must keep 1.5.5 oracle cells identical, else STOP; budget-mode keys on the budget limit; downgrade (admission) + cut-stream (mid-stream) coexist; checkpoint = Durability unit.accrued; Abort = PostingFlags::CUT; the session one-line is MONEY-CHAIN's.
- K6 approved: duplex sessions, two plane tickets, R-B single driver ticket, SessionCaller trait (shared with INBOUND-LISTEN + MCP stdio), turn legs = K2 walk under ONE admission within the destination set sealed at open (option A), one cleanup exactly once, K6-4 $ after MONEY-CHAIN C5.
- DECISIONS D8: PlaneCfg::listed_models (default empty), all configured decisions models listed (scope-filtered). D8b lifts the 'exactly one model' mount: route by request model; one model + none = default (byte-identical); >1 + none = 400; unknown = 404.
- H3 approved: HostServices unit_nest/work.*; UnitFrames by (label,ticket); NestRoute root seam; WorkOpenIn.into = 128-bit ref; child accrual 0 at admit, reported units at exit ($ on MONEY-CHAIN TD13); reserved work:{max_live,retain_s} lifted like pools; in-memory work book (legacy parity).
- FOLD-LLM2 approved: Wave B (B1-B8) now on k1; 34a = PlaneTail sparse refusal_statuses override list (validator + REDs); dev cargo feature llm-on-driver as the switch (deleted in D3); both-paths oracle. Owners: K3=MONEY-CHAIN, A8=K2, B6 verify = busbar-auth-webhook-signature (+ standard-webhooks variant, TWILIO-DOOR), K7 staffed.
- K5 approved: ProjectIn.rewrite/ProjectOut.rewritten (plane applies + re-projects); plane-flattened PromptView messages; hook stages at the head of route_leg after admit; HookVeto carries the hook's clamped status/text; FarEnd candidates()/constrain(); neutral hook engine relocated (GRANT 2, net-flat), shared by the driver and legacy llm.
- DECISIONS D8b: REQUEST_PTRS += /model (metadata); upstream_model rewrites ONLY the top-level model value by span splice when set and different; otherwise byte passthrough.
- AUTOBAHN blocked: Latchkey CONTEXT quota exhausted until 2026-10-01 00:00 UTC, no local docker; re-run after reset (harness armed).
- 34a (a'): PlaneTail RefusalStatus{dialect|ANY, reason, status} (exact->ANY->K1 default) + RefusalIn.reason; HookVeto status comes from the hook (K5), not the table; one joint RefusalIn contract commit with K5.
- K1: sole driver = adbdf5dde6f714cc1 (clone a5dd5142404ac8667 told to stop). K7 approved: pure schedule now; FarEnd-bound after K2's sha; Member.health from the 1.5.5 lane health config; test-only plane (plane-example is being deleted).
- K1 sole driver = a5dd5142404ac8667 (adbdf5dde6f714cc1 was resurrected by a message, now done). New rule: message only roster ids.
- AUTH body: FACT_INBOUND_NEEDS_BODY=8 + VerifyIn.body Blob (only when declared, bounded; over bound = refusal) + VerifyView::body; coordinated with WIRE-AUTH; Twilio signed POSTs enabled once the body is available.
- K7: bd594da94 (pure probe cadence, 9 tests) on k7-probe; resumes when K2 messages its K2-4 EgressFarEnd sha.
- WEBRTC spike GO: str0m 0.24 (no fork, DtlsProvider split) + dimpl 0.7.4 on ring (297-line adapter, DTLS 1.2); 13 new crates; EXCEPTION: aes/cipher/inout for the SRTP KDF only (ring has no raw AES block), confined by a dep-closure test; SRTP GCM-128/256 only, AES_CM refused; the framer gets the public cert DER; bind_path carries ufrag/pwd so core verifies STUN MI. C3/C4/C5 standalone now; C1 + wiring after connector-19/inbound land; headless Chrome+Firefox cells.
- WIRE-STORE Q9: OpenedStore{records bridge, calls: Option<StoreCalls>}; StoreAxis incl default_module; OpIdMint from the kernel's one node allocator. RootRows -> named struct RootInstall (BOOT-CHAIN), axes as named fields.
- Step 21 seal-time half (OutboundAuth open/fields + per-generation MemberRoute table) is OWNED BY K2 (a9d6acf5b3b80f9f7), per the K2 Q2 ruling 2026-09-30.
- WEBRTC C3 = host udp.rs in core-connector (no HOT carrier crate); the udp claim door lands with the wiring after connector-19.
- Test doors: a dropped-in door in tests comes from a built cdylib that is dlopened, never from a linked dev-dep with the export feature (dup busbar_plugin_door from 0128b419a; CONNECTOR-19 owns the fix).
- WIRE-STORE C5 stacks on wire-auth-1b + wire-export (..d9b6871e4) + BOOT-CHAIN RootInstall; landing order is fixed, no duplicate copies of LinkedEntry::Door/load_dropped_bytes/RootInstall.
- MCP session binding = Owner{principal: actor_id, credential: gov.key.id | "<ungoverned>"}; no 'tenant' noun; mismatch = 404 on all paths; ungoverned chain unisolated (documented).
- WARDEN grant rules (2026-09-30, unattended, OWNER REVIEW in final report): G1a-d tier columns, G2 claims.rs transport const, G3 root Cargo.toml manifest lines APPROVED; G1e root-only (kernel×plugin-loader REFUSED, drain). R1-R4 drains owned by WARDEN (plane-word mask, std Tcp* mask, OpenAPI http mask, longest-match needle fix, 'later' rewrite).
- AUTH-SPLIT: auth column first measurement = baseline under GRANT(1)-extended (new column); 8 new-crate first cells + 15 existing-crate items ledgered as DRAIN (owner WARDEN), own commit. OWNER REVIEW.
- MCP sessionless GET+SSE: MCP-Protocol-Version present (streamable rev) -> 405; absent -> legacy 2024-11-05 stream; plain GET/DELETE w/o session -> 405 (ingress_tests).
- WIRE-HOOK C1: contract re-arm 25143->26949 APPROVED GRANT(3) (kernel 55163->55053), own commit with code/test/relocated breakdown; SDK Decoded views MUST borrow (hook body zero-copy law) — held pending confirm.
- WIRE-STORE Q10 OpId: kernel door::op_id(), node half = per-process OS-CSPRNG u64 (nonzero), counter = process-global AtomicU64 from 1; no new crate; $ commit w/ full money proof; RED = cross-boot no collision + S4 replay. Open check: does UnitKey reach durable dedupe?
- Landing order: sdk-safe < STEP-20 G1/G2 (rebased on sdk-safe) < GRPC http->kit switch; grpc kit (b79aaf8cd d2b7b2bae 85d0b13b6 + GRANT3 re-arm) may land on sdk-safe+G1 independently. contract feature sdk-hyper approved (default tree unchanged).
- composes_over: framers (http, grpc, ws...) state EMPTY composes_over; carrier is the connector's choice from the target scheme ("no transport names another"). Earlier ["tcp"] note superseded. http door changes in GRPC-DOOR's switch.
- TRANSPORT-UNIX: `unix` collision mask owned by WARDEN (priority); unix egress bypass only for operator-configured ExactPath (RED for plane-supplied path).
- Latchkey 00:53Z 2026-09-30: still quota-exhausted (5MB probe refused; 352KB left); resets 2026-10-01T00:00Z. Context-less creates are NOT quota-limited.
- 2026-09-30 PACE: LANDER5 lands non-$ READYs as a TRAIN (4-6 stacked, one combined lk proof, bisect on red); $ alone. Priority bases: connector-19, sdk-safe. Kernel/contract/$ READYs get a fresh Opus REVIEWER verdict before landing.
- BLOAT LEDGER (owner watch): contract ceiling 25143 -> 26949 (WIRE-HOOK, pending zero-copy), sdk-safe +461, grpc sdk-hyper pending. Report cumulative in final report.
- 2026-09-30: meter masks+longest-match -> METER-FIX; WARDEN = grants + prose rewrites. K5 Q6: ProjectOut += end_user AbiStr approved.
- FOLD-LLM2 GAP1: ArriveOut.refusal u32 plane-local opaque; RefusalIn += unit u64, plane_code u32, retry_after_s u32 (one layout edit, fold-llm-b). No new kernel ReasonCodes. GAP2 (driver passes kernel Refusal message + retry_after) owned by K1.
- FOLD-LLM2: ArriveOut += refusal_status u32 (400-499 only on REFUSED, 0 otherwise; driver uses+audits), size 120->128, same layout commit.
- GRPC kit -> own lib crate busbar-transport-kit (no ABI shapes; contract sdk-hyper feature deleted; resolver-2 unification leaked hyper into planes). grpc door lands WITH its root row after CONNECTOR-19; GRPC-DOOR deletes legacy GrpcTransport. FAM_GRPC edit approved.
- Latchkey job-creation quota 120/h org-wide is the new binding limit: batch commands per job; warm-cache one per train.
- H2: DemotionRecord key = (instance label, counterparty); unprefixed 1.5.5 rows read only by the default (upgrade-mapped) instance. Kernel +648 must be broken down + reviewed for bloat.
- M5 STORE-MIGRATE: MONEY-WAVE3 (ad2b664c2d44bf0de) extended to build store-kind migration conformance harness (1.5.5 row fixtures -> byte-identical money reads), store-memory first; store ports inherit.
- KIND-SHARE aafb7a126aef5c454 (opus): generic kind-neutral lifecycle slots in abi/sdk/door + one KindAxis; design to ARCHITECT first; WIRE-* hold boilerplate. WIRE-HOOK C2 must lend body via Lent (host NO_BLOB today).
- OWNER 2026-09-30: NO cargo guard on PATH. PERF: EC2 allowed for performance testing, but CHAT WITH OWNER FIRST — owner has a proven perf-testing method to adopt (Phase 6 waits on that chat). WebRTC deps ACCEPTED EXCEPT libopus: Opus pass-through only, no C dep.
- WIRE-SECRET: re-arm own delta after SDK-SAFE; mcp ports-only 285->287 net-0 approved; secret kind live (env/file in-tree), root×secret allowed, kernel test-support rows = drain; new-column baseline GRANT1-ext.
- WIRE-AUTH: ReasonCode::VerifierOverloaded -> 503 unavailable approved.
- Proof rule: build --workspace --all-targets before crate tests (fixture cdylibs). WIRE-HOOK C1 released (contract 26980).
- WIRE-AUTH withdrew VerifierOverloaded: admin adapter checks Prepared::overloaded() before loop -> 503 unavailable; no vocab change (accepted). STORE-MIGRATE: harness in plugin-loader tests; 1.5.5 fixtures written by the pinned 1.5.5 binary via oracle engine (no legacy wire in 1.6.0 loader); memory = no-legacy arm.
- WIRE-EXPORT: `streams` -> BARE_WORD_COLLISIONS (export ABI word), own commit. REVIEW PASS: DIFFS-FIX.
- FOLD-LLM2 Q1: OpenIn.settings = one validated JSON {section:value} per open/refresh, secrets stripped; TD35 kernel copies deleted by FOLD-LLM2. Q2: OnPieceIn += pool AbiStr (K2 fills). Q3: ArriveIn += method AbiStr; plane declines 405. Q4 (K1): order route->authenticate->size gate->arrive (1.5.5 401-before-413).
- DECISIONS D9 ($): decision class = 1 per successful (settled) answer, all providers; hosted keeps 1.5.5 /usage/units as decision count, no tokens. busbar-llm×plane rise refused: move assertion into plane-llm tests.
- M5: ONE shared 1.5.x->1.6.0 row fold in contract store SDK (relocation vs #33), per-backend migrate() calls it; crash-idempotent re-fold test; M5 hard precondition for store siblings opening 1.5.x DBs and for M6 adapter retirement. REVIEW PASS #33/#34. Contract re-arms re-measured after #33 (25082).
- FOLD-A2A C1: plane pair net0 approved (F12); transport +3 refused (move HTTP_TRANSPORT to claims.rs, neutral test URLs); legacy +1 'busbar-a2a-card-' approved TRANSITIONAL (drains with busbar-a2a deletion) — OWNER REPORT. Passthrough section refusal -> kernel validation (FOLD-A2A owns). a2a tonic grpc.rs deleted by GRPC-DOOR.
- REVIEW PASS SDK-SAFE. Published<T> dangling-pointer design flaw -> owning builder, owner KIND-SHARE. WIRE-HOOK C1 re-held: rebase on sdk-safe, drop duplicate safe layer (ruling 366).
- PERF PLAN owner-agreed 2026-09-30: see perf-plan.md (benchmarking repo, openai->openai 1 cell, 1.5.5 baseline must match onthebench.ai, PGO+BOLT+LSE parity mandatory, profile CPU+alloc, iterate to >=2x 1.5.5; at END only).
- FOLD-A2A: PlaneDeclaration += caller_credential_refusal Option<&str> in plane v1 tail; kernel refuses reserved upstream_credentials=passthrough emitting plane's sentence verbatim.
- OWNER 2026-09-30: run 1.5.5 openai->openai baseline NOW; document methodology (perf-methodology.md) for identical 1.6.0 run. PERF-BASELINE staffed (sonnet).
- H2 BLOCKED by REVIEWER: records keyed (label,kind); ThreadOffload -> bounded spawn_blocking, FAILED on failure; DemotionRecord write via Offload+Later; (label,counterparty) key; signing-domain collision refused at admit.
- KIND-SHARE design approved: Life/Held/Leases/fail/settings_object + 9 generic slots; KindAxis assoc types; dispatch::life; RootAxis<K>; Publish arena held to generation retire; C5 = SDK-written out pointers (close safe-surface hole); Q2 unknown-lease release=REFUSED, DRIVE/validate/CANCEL per-kind const.
- OWNER: perf loop runs until we MAX OUT; 2x 1.5.5 is the floor, not the stop. Owner prefers fewer acronyms in reports.
- OWNER: perf goals have NO hard numbers: fastest possible, lowest possible peak memory; binary size not a goal. Supersedes PERF-3 fixed gates (15MB, size<=1.5.5).
- WEBRTC: webrtc-conformance/subject off-tree approved; unregistered-wire standing row transitional; SRTP latch refused (verified ICE check only). 11 new crates for owner report (no opus).
- STEP-20 READY A/B relayed; ws×transport 52->53 transitional (ALPN wire-literal; METER-FIX mask). BEDROCK must also run llm-families strict oracle.
- UNWIRED staffing (INTEGRATION ledger): U1-U5 CONNECTOR-19 (next slice); U6-U8 K1; U9 WIRE-HOOK C2; U10 H2; U11 KV-FIX; U12-U16 MONEY-CHAIN. Hazards: H1 BOOT-CHAIN publishes ONE RootInstall named struct now; H2 keep dispatch::boot; H3 WIRE-STORE drops duplicates; H4 GRPC-DOOR check_agreed; H5 INBOUND-LISTEN serve path.
- POOLS-VERBS kernel re-arm 55182->55251 approved (GRANT3).
- TRANSPORT-UNIX residue: claim literal first cell (GRANT1), root edge (G3) approved; UNIX_EPOCH -> METER-FIX os_words; faces RED (connector HostWire implements plugin Transport face) -> CONNECTOR-19 must use a connector-internal trait.
- K2 review PASS w/ follow-ups: target must start '/', auth fields wait bounded by deadline, zeroisation, passthrough upstream_credentials owned by K2, trailers passed to planes (not dropped); kernel +990 breakdown required.
- MONEY-CHAIN U12-U16: wire into existing GET /api/v1/admin/verify (1.6.0 surface): U12 real CheckpointAnchor, U13 boot recheck findings, U14 GET /audit unchanged + AuditChain verify into /verify over retained records (#82/597), U15 AmendJournal verify finding, U16 resume-breaks drain+diag. No 1.5.5 byte changes.
- AUTH-SPLIT REVIEW PASS. K2 step-21 switch-over must delete kernel egress_auth copies in same train; sigv4 signs real method+query on K2 walk.
- INBOUND-LISTEN: connector×transport +6 transitional (std Tcp* mask); H5 (a) one InboundBind list incl root data door; pre-K1 REFUSE boot on plugin inbound need; transport emit input += status u16 (no ":status" magic header).
- K5 Q7: hook order = 1.5.5 tag per plane (per-attach order if 1.5.5 differed); hooks::policy relocation F12, kernel re-arm GRANT3.
- CONNECTOR-19 pre-review: faces BLOCK (HostWire impl Plugin/Transport -> internal trait); write back-pressure cap (Pending); dial judged under need's own egress_class; mTLS identity parse failure = boot refusal.
- CONNECTOR-19 faces: Option R — HostWire internal surface; legacy Transport face adapter RootWire in composition root (transitional, deletes at step 36).
- MCP-COMPAT pre-review PASS; per-owner session/byte quotas; ungoverned+legacy boot diagnostic; drop getrandom fallback (host CSPRNG only).
- Landing order: connector-19 before boot-chain; BOOT-CHAIN rebases & resolves code conflicts; H6 Dispatcher built once, held, reachable via RootInstall. step20-wire-golden 474f679e7 must NOT land.
- EmitIn status u16 @124 + _reserved u16 (size 200). MCP ungoverned warn = per-instance latch on first legacy stream.
- U17 WIRE-AUTH root rows for header/sigv4/oauth. U18 busbar-auth-hmac VerifyPlugin -> AUTH-SPLIT agent. POOLS-VERBS derive literals. WEBRTC: ICE check = round-trip success response only; zeroise keys; gate app data on peer_verified.
- U18 withdrawn: busbar-auth-webhook-signature (TWILIO-DOOR) is the one inbound-signature auth plugin. U11 = B: trust_keys come from the plane-kind PlaneTail; the hot PlaneDecl never grows. H6: dispatcher() is the one accessor; the RED ships with the first axis on RootInstall.
- GRPC-DOOR: busbar-transport-kit crate withdrawn (breaches #40(a) closure, transport->transport edge, vocab spill). Ruling (c): busbar_contract::hyper_io! macro_rules in the contract SDK area, expanded in each framer against its own hyper/bytes deps; the contract gains only dev-deps; GRANT 2 + GRANT 3; REVIEWER required. (d) law exception refused.
- OWNER: perf paused; perf phase done together with owner. Finish all non-perf work first.
- OWNER SEQUENCE: (1) code 100% done -> (2) perf phase together with owner -> (3) DEV done. DEV-GREEN is NOT declared before perf.
- A2A-PUSH 3e694d691: a2a×kernel 66->68 / ports-only 237 rise REFUSED; FOLD-A2A reworks it through the ports. Re-arms at LANDER-measured values: kernel 55168->55337 (KV), contract 25082->25543 (SDK-SAFE) ->25712 (KV).
- LANDED #33 ($) 5f235745a + 7f38e2e60 + cab747f6d; predev tip cab747f6d; contract 25082. MONEY-WAVE3 -> STORE-MIGRATE.
- AUTH-SPLIT HELD: lands in the same train as K2's switch-over deleting kernel egress_auth copies (no two implementations on predev); a parity commit (AWS sigv4 vectors + oracle cells) is required first. RustCrypto accepted as inherited. STEP-20 (A) contract piece d1cdb1cf8/5477ad47e pulled from train 3 pending REVIEWER.
- OWNER-REPORT: transitional ws kind-isolation 52->53 (STEP-20) must be listed in the final report. STEP-20 (A) REVIEWER PASS.
- inbound-status 944c2e5a5/ab9b83056 REVIEWER PASS; check_emit_status must be wired with a RED in the first H5 commit that sets status.
- FOLD-LLM2: RefusalIn.target AbiStr approved (the plane renders unit-less refusals per its path rule = 1.5.5 residual). GroupFrozen pinned to the 1.5.5 403 text + NEW golden cell recorded from the 1.5.5 binary; list other cell-less reason arms.
- OWNER-REPORT (perf session): 1.5.5 board baseline lacks BOLT/+lse; ask whether to also bench 1.5.5 rebuilt with the 1.6.0 build settings. The rig box qualifies 7.8% slower than the board box; compare on the SAME box.
- MCP-COMPAT C4: busbar-mcp×plane 3877->3891 REFUSED; move new session_serve into busbar-plane-mcp or offset to <=3877. ports-only-tests 188->185 re-pin approved (lowering).
- BOOT-CHAIN GRANT 3: contract 25610->25627 (claims field), kernel 55163->55179; re-measure after the connector-19 rebase and at landing.
- Pre-arrive refusal status: (iv) each declared route carries an opaque refusal_dialect u16; the router sets RefusalIn.dialect before arrive. Refused: provisional arrive on unauthenticated bodies, plane-stated status, kernel path rules. FOLD-LLM2 contract, K1 router.
- WIRE-HOOK: fixture self-build (silent-skip root cause) approved; C1 contract 26988->28768 GRANT 3 needs REVIEWER; C2 (a)-(d) now, axis wiring last. abi/sdk/held is the shared helper. METER-FIX: union ceiling derived (a); delete kernel warn_capture dup; the LOC basis shift (kernel 52018/contract 23371) means all re-arms are re-measured at landing.
- OWNER 2026-09-29: 1.5.5 baseline ACCEPTED as within margin of error; methodology confirmed. The 1.6.0 comparison reuses it (same box type/region/filter).
- K1 READY (plane driver + contract plane_calls): needs REVIEWER; lands after RENAME via the on-rename variant (no kernel×plane rise). Next order: U8 -> U6/U7 -> C4 -> GAP2/Q4+refusal_dialect.
- OWNER: perf results always reported machine-adjusted (gateway rps / no-gateway rps). The 1.5.5 baseline is +1.5% vs board when adjusted = identical.
- K1 BLOCK (REVIEWER): on_piece used submit without a lent owner (use-after-free on watchdog abandon). Order: LENT-KEEP -> RENAME -> K1 reworked on submit_lent for every abandonable crossing, with a RED.
- fold-llm-b REVIEWER PASS; required follow-up: wire reason codes -> explicit repr(u32) append-only table in abi/ with a pinned test + RED.
- INBOUND-LISTEN: data + admin root listeners both in the InboundBind list and both bound via Connector::listen (admin keeps its separate router; RED). Root binds uncapped; --validate prints plugin listeners only.
- kind-isolation entry-count: (A) the door tail counts as the entry (impl Transport + TransportTail). The ws 2-entry finding is recorded as transitional until TRANSPORT-STACK. End state: door only.
- ORACLE-CELLS staffed (opus): 1.5.5 add-only golden cells for the uncovered ingress refusal arms (Disabled/MissingGroup/concurrent/tokens/pool-scope/PoolNotPermitted/Unpriced); busbar-release push via LANDER.
- Egress response head fields cross to the plane (first FarPiece + Buffered + send_pinned_stream), plane-neutral, K2 owns; hop-by-hop and credential headers never cross. MCP-COMPAT C4 accepted (busbar-mcp×plane 3872).
- Response headers to planes: each plane DECLARES keep_response_headers at boot (validated: no hop-by-hop or credential names); the kernel copies only those into the egress head. K2 builds it; MCP (mcp-session-id) and llm (1.5.5 pass-through set) consume it.
- CORRECTION: abi/sdk/held withdrawn; KIND-SHARE life.rs is the one lease/error helper. Hook and store keep their local copies until KIND-SHARE's port deletes them.
- claims: Statement.claims is the ONE source; the transport tail claims field is removed; a non-transport Statement with claims is refused at admit (BOOT-CHAIN).
- Response head fields ONLY on the FarEnd path (FarPiece.head + OnPieceIn list); the legacy seam.rs egress is NOT extended (dead lane). CONNECTOR-19 makes the connector yield a Fields piece (response head); K2 filters to the plane-declared keep_response_headers (≤32, lowercase, no hop-by-hop or credential names).
- hook.call op 17: K5 owns the ABI+host (PromptView, GATE=0/REWRITE=1, calling unit's container gates). WIRE-HOOK: MemoryHook RoutingPolicy adapter, tap as THE notify path (delete the JSON notify path if unused), RoutingRequest.body Arc lent. K5 Q7: 1.5.5 hook order only.
- Disk: 22 idle target dirs deleted -> 172G free.
- claims refined (A): Statement.claims = names (one source); transport tail claim_rows parallel by index (metadata, no key); admit refuses a length mismatch; a non-transport Statement with claims is refused.
- OWNER 2026-09-29: no extra build capacity; stay on Latchkey and check it as soon as the quota lifts.
- H5: the connector Listening is the one listener source; the root stream hand-up (poll_accept_stream) is permanent for ADMIN and transitional for the DATA door until K1 U6/U7 (Connection::accepted). check_emit_status is wired by K1 in the commit that first sets status.
- K2-6 split: non-$ root::plane_egress (Connector, needs, Egress sealing) then $ NodeEndPost+PlaneMoney alone. ONE root Connector shared by inbound (H5) and outbound (K2), built once at boot (RED: same instance).
- FOLD-LLM2: plane naming the http crate REFUSED (planes are transport-blind; use the ABI field shape); alt=sse and cell-id strings -> METER-FIX masks; target plane-llm×transport <=792. ports-only-tests busbar-llm 990->991 approved under GRANT 2 (nets down, drains at D3).
- warn_capture dup: stays as a transitional row until step 36 (migration now would raise kind-isolation); patch kept at meter-fix-warn-capture.patch.
- GAP: production planes load via the dead hot PlaneDecl lane; BOOT-CHAIN moves open_planes onto load_linked/load_dropped::<Plane> (Statement+tail -> plane row) and deletes the hot read path; KV-FIX adds the U11 RED after. KV-STRICT+TAIL relayed.
- INTEGRATION smoke test GREEN on b461d61b1 (20 llm arms/5 dialects + mcp + a2a). busbar×transport 693 is a transitional row, drained to <=689 (METER-FIX Tcp* mask, loopback URL via the test helper, capability-gated tool arm). Smoke test in the default test set.
- hook.call: chain resume via from:u32 (0 = unchanged, 1+i = rewrote, 400-599 = stop, cap 255). SECURITY: gate scope comes from the CALLING UNIT (kernel-recorded plane+pool), never from view fields; a resumed chain is pinned to the unit's config generation.
- H2: 1.5.5 unlabelled demotion rows map to the plane's implicit first instance (label = declared section key), resolved at boot; K1 passes it into with_demotions.
- lk-cached.sh: jobs default XTASK_CEILING_BASE to merge-base(HEAD, origin/predev) (the no-base posture RED was a detached-HEAD artefact). GRPC-DOOR macro prefix REVIEWER PASS.
- FOLD-LLM2: plane transport-blind (plane-llm×transport 798 = 792 + 6 mask hits). contract×transport +1 transitional; drained by switching DialectCodec/ClaimsFn to HeadFields after BEDROCK-INVOKE lands (the contract then names no http).
- LANDED TRAIN 2 (non-$): predev cab747f6d -> 23d8a6b46, 32 commits (PREDEV-REDS s1, REAPER, LENT-KEEP, WIRE-AUTH-1b, DIFFS-FIX, SDK-SAFE, KV, C0, STEP-20 B). kernel 55337, contract 25712.
- DialectCodec/ProtocolDecl move out of busbar-contract into busbar-plane-llm (with the HeadFields switch, after BEDROCK-INVOKE); kernel/root users go via the plane ABI or become transitional until D5/D3.
- twilio-auth REVIEWER PASS. Owed: e2e RED (no sig -> 401); kernel must refuse all-abstain auth (WIRE-AUTH); Twilio replay matches 1.5.5; standard-webhooks webhook-id replay rejected via the claim record. WIRE-AUTH contract re-arm owed.
- A2A-PUSH accepted (counts ≤ base, ports-only 236->235); the real kernel reach (EngineHost) must move to the plane ABI host services when push-deliver folds into plane-a2a, drained at D3. fold-a2a-c1 READY (net down).
- Auth replay: kernel-side (B). Identity gains replay_key+replay_ttl_secs; the verify caller claims records('auth-replay', plugin/key, ttl), TAKEN -> 401. Twilio: no replay rule (not in 1.5.5, no nonce).
- MCP-COMPAT C1-C4+C6 READY (4/4 real SDK peers on serve). The client leg moves onto FarEnd at FOLD-MCP's flip; C5 adapter handed over; boot.sh heredoc fix assigned. MCP-COMPAT used pkill -f (rule broken; reminded).
- WEBRTC: land C3 udp + C4 dtls + caps + hygiene now (connector-only); hold the C5 framer + browser cell for the root-row train (registration). The standing unregistered-wire ruling is withdrawn (the gate doesn't honour it).
- WIRE-HOOK C1 READY (REVIEWER PASS). C2: RequestBody newtype (zero-copy Bytes) approved; the final axis commit deletes the JSON notify path + DlopenPolicy and adds a RED that a 1.5.5 JSON hook plugin is refused at boot.
- CONNECTOR-19: READY stack+RootWire first (rebase 23d8a6b46), U1-U5 after; head Fields split to a new HEAD-FIELDS agent (opus).
- OWNER 2026-09-29: proof policy approved (agent = workspace build + touched crates + affected gates; LANDER = the single full proof; $ keeps the full proof on both sides).
- Train 3 bounces: WIRE-STORE C1 (test imports API #33 deleted) and STEP-20 A (7 wire cells vs 1.5.5: h1 port normalization, h2 HPACK + SETTINGS ack must match 1.5.5 bytes). New proof policy broadcast.
- A17 accepted difference: cells regex widened +3 (anthropic missing-group/budget-total/budget-pool: insufficient_quota->billing_error), same signed rationale; OWNER-REPORT item. FOLD-LLM2 codec series (a) HeadFields/u16, (b) the ABI at the flip, (c) traits into the plane at D3.
- MONEY-CHAIN: READY done work now (non-$ group + C1/C2/C6 $ alone). U14 audit seal/body/decoder/verify = MONEY-CHAIN after MW3's v3. Incarnation goes into the v3 preimage if v3 is unlanded (MW3), else v4 in U14; RED: two boots, same unit_key -> distinct.
- GAP: no production plane exports a plane-kind door. BOOT-CHAIN P1 = load path for door-exporting planes now (HOT-only planes transitional M6, drained per fold); P2 = delete the HOT read path with the last fold. EVERY fold's flip ships its plane door + linked door row (llm, mcp, a2a, decisions, streaming). Streaming fold was UNSTAFFED -> FOLD-STREAMING spawned.
- STORE-MIGRATE READY ($): 1.5.5-written sqlite fixture read back identically; -> REVIEWER then lands alone. Legacy 1.5.5 store wire retires at M6 after every backend passes; network backends must run in Latchkey (MW3). Digest v3 already landed -> incarnation = v4 in MONEY-CHAIN U14.
- FOLD-MCP F25: predev is the MCP baseline (MCP-COMPAT exceptions). Keep subscribe for old revisions; fix all 11 plane gaps to predev; meter() must equal predev ($); session-id per MCP-COMPAT. Homes: stdio supervisor -> stdio transport; RFC 8693 exchange -> auth-oauth (AUTH-SPLIT); rmcp vocab test -> mcp-conformance; tools grammar = plane; task store = host records.
- GRPC head/trailers: the head carries no HAS_CODE; trailers = Fields|HAS_CODE(grpc-status), then a terminal piece (empty OK / STREAM_FAILED+grpc-message), bytes = 1.5.5. Request pseudo-headers go in typed head slots, never fields; te is checked at the door per 1.5.5, then dropped (hop-by-hop). HEAD-FIELDS: an empty Fields head carrying the status, always first.
- STORE-MIGRATE REVIEWER PASS (5e03dadb1 alone). MEDIUM -> 4th commit: CI=1 panics on missing fixtures/cdylib + a CI step runs store-migration-fixture.sh. Rebase onto predev.
- K2-5 3315c7dd3 BLOCK: checked add + refuse duplicate classes (REDs); abandoned Open entry leaks; EndPost exactly once; flat-fee cancel refund = 1.5.5 cited.
- FOLD-MCP F25 applied: 12 retire, 13 re-homed; 21 RFC 8693 tests -> AUTH-SPLIT.
- CORRECTION te: 1.5.5 (tonic 0.14.6 + h2 0.4.18) serves a missing te; a wrong te is reset by h2 PROTOCOL_ERROR; the door drops te. Cells: te=gzip reset, missing te served.
- 2026-09-30 LATCHKEY: burst of ~20 jobs in 4.5 min (03:20-03:25) hit the quota, and nothing queued after 03:25. The shared 100/h limiter is added to lk-cached.sh (backup .bak-2026-09-30-rate); the ONE-JOB-PER-PROOF rule is in agent-rules.
- OWNER 2026-09-30: '2 per min is crazy', use it efficiently: limiter tightened to 45/h for agents, 90/h cap with LANDER priority (LK_PRIO=1).
- ACCEPTED-stream RequestHead (HEAD-FIELDS, A): typed repr(C) RequestHead{stream, method, target, authority-or-neutral} spans into FramerSink.frame, yielded with the first Fields piece on SIDE_ACCEPT; the kernel fills ArriveIn.method/target from it; pseudo-fields in Fields refused. Framers' accept emission is owned by INBOUND-LISTEN (http) and GRPC-DOOR (grpc).
- K5: production PlaneDriver+KernelServices composition = ONE place, K1 serve path (U6/U7); folds add only door rows. K5 drops cherry-pick c87abc4b6 after K2 lands. 178 v1.5.5 hook tests verbatim on the driver = llm flip gate (FOLD-LLM2).
- NanoJev: /api/evaluate = second exact claim; model dialect = override or provider protocol; a wrong-dialect model gets that dialect's existing unknown-model refusal; metering = the upstream's own billing unit, counted from the answer already read (no extra egress); shared in-plane error reader; E4 refusal.
- U13: delete the recompute cache arbitration (unconstructed); covered by reconcile_with_journal + RED; restart findings surfaced via audit/metric/log unless /verify is new in 1.6.0. Export repos re-pin to current abi/export -> WIRE-EXPORT. transport-tcp repo (abi::hot) is superseded by in-tree busbar-transport-tcp at step-40 extraction. 10 port agents staffed (store x4, auth x3, vault, hook x2).
- http accept-side RequestHead emission -> STEP-20 (owns the http door); INBOUND-LISTEN stays on H5 and consumes the slots in the connector.
- PORT GAPS (shared mechanism): every kind's Tail gets needs; the safe SDK gets Pending/redrive + HostConns for every kind; exchange() is an SDK helper -> KIND-SHARE. Loader fills HostTables.conns for declared needs -> BOOT-CHAIN. StoreSlots Pending-capable, one checked-out conn per op -> WIRE-STORE. Q82 realization = a sans-IO codec over the host stream (mysql_common core; an ldap3_proto-like codec for ldap), never a blocking driver.
- Streaming: caller_ref = opaque keyed per-principal ref on plane arrive/open (the privacy fix vs predev's raw principal); the auth reply gains generic query params + outbound style query-key (WIRE-AUTH); the streaming plane serves its protected-resource metadata doc.
- PORT RULINGS R1-R8 are in port-brief.md (dev-pin, shared mechanism owners, kind SDK owners, DB wire = plugin logic over conns, sqlite opens its own file, migration harness owner, 1.5.5 diffs in their own commit + QUESTIONS, config keys never move; exchange() is FRAMED http).
- OIDC JWKS: sans-IO single-flight — a cold kid pends verify, one fetch via exchange(), all waiters wake; tick refreshes ahead of TTL; 1.5.5 timings.
- A2A: ABI Claim gains CLAIM_PATTERN ("{…}" = PathSeg::Var) mapped to Selector::PathPattern, CG-62 precedence (FOLD-A2A implements).
- STEP-20 accept-side order: CONNECTOR-19 -> head-fields -> GRPC-DOOR macro fill() heads -> http accept; cells: http.crosscut + routes + inbound families.
- OWNER-REPORT (QUESTIONS): auth-github dev adds a `github:id/<id>` role vs 1.0.3 (anti-handle-reuse fix) -> kept in its own commit per R7, owner to sign or drop; ldap carries 3 owner-signed diffs from 2026-09-28.
- ORACLE HOLE: no inbound h2 cells. STEP-20 records 6 add-only CAP cells from published 1.5.5 (h2c POST, h2 TLS ALPN, te trailers, no te, wrong te reset, malformed pseudo/uppercase reset); LANDER pushes to busbar-release + pin bump.
- caller_ref = OnPieceIn.caller_ref (AbiStr), lent every piece; K2 adds it in the same layout commit as `pool`; the helper is in busbar-kernel-identity: HMAC-SHA256, HKDF-derived key from node signing material, label "busbar caller-ref v1".
- llm flip hook gate = 184/184 on the driver (70 llm-origin via project = FOLD-LLM2; 114 kernel/loader/ranking = K5).
- lk-cached.sh: a refused (quota) submission is un-recorded and self-retries every 5 min (12x); ledger pruned of refusals at 04:04Z; Latchkey reopened 04:00Z.
- lk-cached pacing: 1 agent submission per 60s (LANDER exempt) after a 38-job burst at 04:05Z.
- OnPieceIn += claim:u32 + dialect:u32 (lent every piece, from the arrival), in K2's one layout commit with pool + caller_ref; multi-door planes need it.
- MONEY DEFECT (MONEY-CHAIN): a tampered complete tail WAL record was truncated as torn -> a billed settlement became 0 with no alarm. Fix ($, alone, before U14): framed length + header CRC; truncate only a true torn tail; a complete record failing its body check is quarantined + in restart_findings; never 0-settle a unit named by a quarantined record.
- U14 approved: seal one AuditRecord at the unit's one line (facts from the audit step kept on the unit); recipe v4 = v3 + incarnation; journal audit.v4 body; a 1024 ring is only a cache (older /audit/range decodes from the journal); refused units get a record (outcome refused + step, empty amount); non-$ with the money proof.
- WARDEN-GRANTS READY (G1-G3 rule grants; owner-report). kernel×plugin-tooling 213 owners: BOOT-CHAIN (preflight/config/appbuild), WIRE-HOOK/AUTH/EXPORT (their modules), K1 (router/observe/lib), METER-FIX (test_support via test billing in matrix).
- KIND-SHARE: Statement gains needs (moved from PlaneTail; one check_needs for every kind; no MECHANISM_VERSION bump pre-tag); SDK Connector over HostTables' ConnectorSlots (establish/write/read/close/upgrade_secure, Ready|Pending) + exchange() on it; Held per-ticket in-flight state; generic Open::validate (C6).
- CONVERGENCE ITEM (K2 / CONNECTOR-19, by step 36): the plane lowering ConnSlots/HostConns and ConnectorSlots are two tables for one mechanism (§5); the plane path sits on the same Connector or is deleted.
- auth-replay claims use H2's records.claim (kind auth-replay); no separate ReplayClaims store; sharing = the configured store's reach.
- METER-FIX test billing in the matrix: NARROW only on non-instance axes (plugin-tooling/contract/cleanliness); instance axes keep counting test_support (§1 kind-neutral doubles; false-fail law); BROAD refused.
- STORE (WIRE-STORE): MONEY op_id collision (per-handle counter + durable dedupe drops writes across handles/restarts) -> op_id = (node, boot incarnation, process-global counter), $ alone; plugin refusal text reaches the boot error; StoreSlots::validate only parses (--validate never touches the database).
- NanoJev: decision = execution.states from the answer ($ alone; no-count refuses loud). Plane gets its referenced providers' dialect fields at open (PlaneOpenIn list, §4 'dialect fields go to the planes that use the provider'); the plane resolves model->dialect and selects itself; no kernel dialect check.
- Reserved plane sub-keys gain 'work' (THE DESIGN §4 list); a plane entry named after any reserved key is refused at validate with a clear message (generic check, H3).
- H3 REVIEWER PASS both; the $ follow-up makes the parent/child same-principal check release-mode fail-closed. OWNER-REPORT: inherited kernel×plane +1 (1617->1618) from K1 base.
- No cell raise for word collisions: METER-FIX adds an 'HTTP {status}' status-phrase mask (auth-oauth×transport stays 4); AUTH-SPLIT keeps the exact predev refusal words.
- WIRE-STORE op_id: CSPRNG 64-bit boot half + process-global counter (no journal incarnation, no layout change); LoadedStore takes OpIdMint. disk.append rotation = declared per destination {path_key, rotate_size_key, keep}. Hourly upkeep cron at :17.
- U14 seams: no free Pass<Audit> factory; the audit step's pass travels with AuditFacts via Units::audited(ctx, facts, pass), and the one line consumes it to seal. OWNER-REPORT: the CHANGELOG/#34 owner-signed premise now names digest v4 (v3 never shipped).
- U14 usage classes: all classes are declared (plane) or configured (operator units) at boot and registered once; the one line resolves reported classes via Registration; an unresolvable class = plane fault, refused fail-closed + finding (never dropped, never free text, never 0); the contract UsageLine is kept.
- Class registration: absent-card behaviour unchanged (count rows at 0, as 1.5.5); root fix = planes declare every class they report (declared ⊇ reported, enforced by a test); refusal only for genuinely undeclared classes.
- 2026-09-30 (OWNER): plane seam L — no OP_LOCAL flag; a plane's local answer ends the unit, the pump takes the far member lazily (K1 09490ff9b). R — a plane's refused-arrive text flows into RefusalIn.text: opaque bytes, hard size cap (over = refused), rendered only through the claimant's refusal dialect, never logged or audited. R-addendum — RefusalOut carries a neutral status number the transport maps to its wire. Generations — the plane takes the newest generation at arrive (SDK Generations<T,P>::current()); the kernel refuses a moved unit at ATTEMPT; no generation field in the head.
- 2026-09-30 (OWNER): route match vocabulary (abi/transport) adds PATH_SUFFIX, PATH_CONTAINS and FIELD_VALUE_PREFIX (ported from grammar::Selector). A claimant's declared line order breaks ties among its own lines; CG-62 refusal stands between claimants. Path matched, method not: 405 with that line's claimant refusal bytes and Allow as 1.5.5. No-route: 404 with the listener default's bytes, rendered by the default claimant's `refusal` via a path-shape → refusal_dialect table (opaque data). Auth runs first on both (401 before 404/405).
- 2026-09-30: guest-list order — path precedence (CG-62) is the first key; field predicates break ties only among lines at equal path precedence (so an exact path beats a prefix line with predicates, as 1.5.5's explicit routes beat its fallback ladder); then claimant order.
- 2026-09-30: new-plane refusals follow predev bytes. An unlisted JSON-RPC method is relayed verbatim as predev did, under the op class predev audited/billed it as (RED vs predev), never refused. A refusal on a gRPC line sets RefusalOut's neutral status; the grpc transport maps it to grpc-status/trailers byte-equal to predev. The Origin (DNS-rebinding) check leaves the kernel with ingress/protocol: it is the plane's arrive check, same ordering and bytes as predev. MAX_REFUSAL_TEXT is sized at or above the largest field line the transport admits, so an echoed header can never overflow (RED at the max size). The kernel keeps setting the gate-rejected audit marker; planes never set it.
- 2026-09-30: busbar-kernel-budget is deleted whole (its admission stack has no production caller): arrival_hold moves to busbar_kernel::door beside admitted_at_zero; planes use the kernel's governance::budget_window. no-float-money repoints its budget scan to busbar-kernel/src/governance with ONE named exemption, state.rs rate_headroom (an f64 routing ratio over request/token counts, not money; converting it would change routing), plus a RED that any other float in that scope fails; its file floor becomes the measured governance count. Equivalence d2 and rate_conversion_agreement repoint to the kernel's live functions; qa/capability-equality repoints off AdmissionUnit.
- 2026-09-30: host services — `entitlement.check` (target "<scope_kind>:<name>", against the unit's verified principal held on the unit record; dead key NOT_ENTITLED; ungoverned ENTITLED; undeclared kind NOT_ENTITLED) and `random.fill` (kernel CSPRNG, capped) — H2; SDK wrappers live in abi/sdk/services.rs. SDK `Generations<T,P>` and `Keyed<K,V>` hold per-instance plane state (never process-global); plane purity.rs unchanged.
- 2026-09-30: a2a plane — ONE dialect; JSON-RPC/REST/gRPC are its lines with per-line refusal_dialect; gRPC on its own listener; transport de-frames, plane transcodes protobuf↔ProtoJSON; kernel owns audit rows, request metric, admission and grant filtering. POST /a2a/push is auth `none`; the plane checks its own callback correlation token (never logged/audited). New-plane baseline = predev router + 1.5.5 no-route cell.
- 2026-09-30: request-target encoding follows 1.5.5's url serialisation byte-for-byte (WHATWG path/query sets; CR/LF/tab stripped, NUL encoded). Overload stays 503 (accepted row). wire-auth-land rejected against §6 (kernel called verify, named carriers); wire-auth-neutral + §6 shapes + HeadBody land as ONE train.

- 2026-09-30 PORT hook-webrequest reason phrase: fixed at the root, NOT an owner diff. The KIND-SHARE exchange() response head carries the reason phrase as sent (h1 wire phrase, empty for h2 -> canonical). interpret() uses it -> 1.5.5 texts byte-identical.
- 2026-09-30 PORT hook-webrequest: resolve/pin and the internal-address refusal move to the egress class with a byte-identical 1.5.5 refusal text (KIND-SHARE carries the tests). The configure NACK reason is emitted by the host on stderr as in 1.5.5. None of these is an owner diff.
- 2026-09-30 OWNER-REPORT: WARDEN-GRANTS (9c9b2afef, with LANDER after METER-FIX) changes gate semantics via G1a-e/G2/G3; standing list 138->126; ship-ceiling 19157->17684 hits. Base reds: core-admin 10 hook/registry tests; kind-isolation selftest 2 loader-dep cases -> PREDEV-REDS.
- 2026-09-30 KIND-SHARE exchange head: option (2), a READ_PIECE service appended to ConnectorSlots (abi/host/conn; append, no version bump). One head descriptor agreed with HEAD-FIELDS: {head|body|end, status, reason span, field spans}; h1 reason as sent, h2 empty. CONNECTOR-19 fills it in the host. The egress class (resolve/pin/SSRF refusal, 1.5.5 texts byte-identical) belongs to CONNECTOR-19. ExchangeResponse{status,reason,fields,body}.
- 2026-09-30 OWNER RULING (Matthew): a plugin that sends data must see the response; every transport acks each request back to the plugin, not only http. The READ_PIECE ruling is widened to transport-neutral READ_REPLY {ack|head|body|end, code u32, reason span, field spans} in abi/host/conn (appended). Rules: at least one terminal ack per request; an egress refusal is an ack failure carrying the 1.5.5 text; a missing ack is a conformance failure. exchange() is the http helper; send_and_ack() is generic. Owners: KIND-SHARE (SDK+layout), CONNECTOR-19 (host), HEAD-FIELDS (one descriptor). SPEC FOLD: Part 4 transport kind.
- 2026-09-30 HEAD-FIELDS: the one reply descriptor is {kind ACK|HEAD|BODY|END, code u32, reason FrameSpan, fields FrameSpan over abi::transport::fields}. (A) RequestHead is renamed to the neutral per-stream HeadSlots{stream,method,target,authority,reason}: accepted side fills m/t/a, dialled side fills reason (h1 as sent, h2 empty). FramePiece.status_code is renamed to code (own commit).
- 2026-09-30 23:30 UNWIRED OWNERS: K1=production composition (Dispatcher kept, KernelServices+with_services/admit, PlaneInstance/Axis/Driver in serve); BOOT-CHAIN=Connector::serving at boot + declare_over/unix; CONNECTOR-19=DialJudge bridge + HostWire PIECE_TEXT; FOLD-STREAMING=FrameMeta.text reader + ws write honours text; INBOUND-LISTEN=unary CallerEnd; K5=hook.call; DECISIONS=PlaneTail.trust_keys dropped-in bridge; AUDIT-WIRE a94d9c6cc04502845 (opus, plan first)=audit/ledger verifiers; WIRE-SECRET/EXPORT adopt RootInstall; STEP-20 strips withdrawn fields. Kind-isolation rule: standing row = base measure on METER meter; excess = bounce unless net-zero move. BOOT-CHAIN fetch closure approved. WIRE-AUTH replay via governance RecordStore redeem_plane_token approved.
- 2026-09-30 AUDIT-WIRE a94d9c6cc04502845: W1 approved: /admin/verify ?anchor=<seq>:<hash> puller-supplied SuppliedHead (non-self-attesting, #82 pull model; malformed=400; answer names anchor kind). W2 approved: xtask audit-verify, an out-of-process v4 verifier (TODO 597/B11), after U14. MONEY-CHAIN keeps U12-U16. OWNER-REPORT: the new optional /verify param.
- 2026-09-30 H2 U10: write-behind bounded (<=1s tick, <=N queued; documented crash window); records.claim and replay/idempotency/money writes are ALWAYS synchronous before ack (RED). H9: HostServices append slot order = landing order, the later lander carries all, layout test pins it. WIRE-SECRET stacks on the rebased boot-chain (order boot-chain then wire-secret/export). INBOUND-LISTEN: accepted::Caller impl CallerEnd; head fields = first emit via framer::encode with status on the same emit (no ABI change); C4 stays K1. BOOT-CHAIN (1prime): TrustPolicy::from_config in the loader, kernel warn_invalid_floors; core-admin +<=2 only as a proven net move.
- 2026-09-30 K1 serve composition APPROVED: root/serve.rs = the one production composition; everything constructed every boot, only per-plane serve switches gated (llm FOLD-LLM2, mcp FOLD-MCP, a2a FOLD-A2A, streaming FOLD-STREAMING); smoke asserts composition live; K5 reviews hook wiring. K5 kernel +1666 needs per-file justification + the unprojectable-body edge vs 1.5.5. MONEY-CHAIN: boot self-attesting checkpoint compare (a); decoder-as-reader goes to REVIEWER. AUDIT-WIRE W1 compares against anchored_on_chain (one parser). K6 refusing session defaults allowed until K6-4 (guard RED). HARD RULE 0 added to agent-rules (no cargo on the Mac).
- 2026-09-30 07:00 upkeep: freed 52G (274G free); no local cargo; 42/45 budget; predev still 23d8a6b46 (lander-s proving). Staffed PORT-EXPORTS a6e893653a2080918 (opus) for export-file/otlp/prometheus/webhook re-pin to the WIRE-EXPORT shape (transport-tcp repo superseded by in-tree crate). NanoJev unreadable count = same outcome as item 395 /usage/units ($ alone).
- 2026-09-30 KIND-SHARE: WRITE_REQUEST approved (service 13, the mirror of READ_REPLY; RequestPiece HEAD/BODY/END with method/target/fields/timeout_ms; non-framed transports refuse; timeout clamped to the deadline class). SDK type exchange::Request (no protocol noun). Need shape (egress_class consts, claim words, target_from/trust_from) = KIND-SHARE; egress-class behaviour = CONNECTOR-19. RootWire: classify reds vs predev.
- 2026-09-30 H3 62bcb3b7e HELD: reserved plane sub-keys must not break 1.5.5 configs (R8); names 1.5.5 did not reserve must move out of the entry namespace; RED that a 1.5.5 config with an entry named work loads identically. FOLD-STREAMING: text frames per S3f; prove the 1.5.5 wire opcode; if 1.5.5 sent Binary, the Text change is a DEFECT FIX added as a QUESTIONS owner-report row. OWNER-REPORT: WebRTC third-party crates (C4: dimpl, arrayvec, nom 8 as a second nom; C5 held: str0m, str0m-proto, is, sctp-proto, crc, crc-catalog, aes, cipher, inout).
- 2026-09-30 OWNER-REPORT WebRTC: headless Chrome+Firefox cell 26/26 (DTLS1.2 AES-256-GCM); on a network switch the call survives but the audio gap is Chrome 2.76-2.88s and Firefox 3.5-6.4s (new in 1.6.0, no 1.5.5 baseline; candidate for the perf phase).
- 2026-09-30 H2: RECORD_DELETE retired (no caller; 1.5.5 had no RecordWrite; plane deletes stay on RecordStore seam). H2 kernel 55337->56216, contract 25712->25789 GRANT 3; U10 +45 then lowering. K1 owes KernelServices build + 1s flush_tick + shutdown drain (RED). LDAP: secret via OpenIn.secrets (1.5.5 literal accepted by host), timeout_ms on need, LOGIN_OUTAGE byte-identical to 1.5.5 Reject (WIRE-AUTH). WIRE-HOOK contract x plane +11 BOUNCED (not net-zero). FOLD-STREAMING: ws opcode = new-surface register only; ONE twilio claim (twilio-claim). Local cargo killed: WIRE-HOOK pid 55938; H3 local fmt warned.
- 2026-09-30 RULINGS: C2d plane-originated egress (a2a push, card fetch, admin connect/approve) = declared outbound NEED via HostConns (THE DESIGN §5), connector judges every open, plane keeps retry+queue, no unit/no billing; kernel-originated synthetic unit REFUSED; FarEnd = caller-unit only. C2a validate refusal uses sdk::life::fail (KIND-SHARE), no static placeholder; C2a REFUSED request ops = TRANSITIONAL with TODO row. H3 hold lifted (1.5.5 DeployCfg deny_unknown_fields verified). STEP-20 (A) net-zero at 48, drain in grpc deletion series with workspace-gate RED. DONE-HARNESS item2: accept BUSBAR_RELEASE_CHECKOUT only if git HEAD == full pinned sha + clean tree (no marker files); lk-cached diff applied by ARCHITECT. lk-cached.sh FIFO queue added. S3f text frames: EmitIn flags EMIT_TEXT + OnPieceOut PIECE_OUT_TEXT; no legacy write_typed. WIRE-AUTH admin saturation -> 1.5.5 401 (unsigned 503 register entry removed).

### 2026-09-30 — OWNER and ARCHITECT rulings (this session)
- OWNER-LOCKED (design session with the ARCHITECT): AUTH POINTS AND GUEST LISTS (THE DESIGN §6). The
  kernel owns the listeners (driveways) and writes one guest list per listener from each plane's
  per-dialect claims (route, transport kind, default auth style; operator overrides); transports
  decode, match the route, call that line's auth at its auth points (Head, HeadBody, Peer; Frame
  reserved; defined in `busbar-contract/src/abi/auth`), strip the credential lines the auth names,
  and hand the request in with the matched line; the kernel checks the line, owns the verdict and the
  refusal. Outbound: each binding has its own transport and auth; finalise, auth, encode, nothing
  after. Replies return by unit ticket; lists and bindings are per generation. Law 1 gains the
  vocabulary rule. Review 2 (adversarial, SIGN-OFF-WITH-FIXES) applied: fail-closed line check,
  core/cleanliness claimants, CG-62 route matching, 1.5.5 auth.chain as the line auth, upgrades, unit
  minting.
- OWNER: plugin repos are exact TWINS — public, Apache-2.0, default branch `dev`, identical skeleton,
  generated and checked by `cargo xtask fleet` from `plugins.yaml` + `.github/fleet/`. New repos:
  busbar-plane-{llm,mcp,a2a,streaming,decisions}, busbar-transport-{http,ws,stdio,grpc},
  busbar-hook-ranking, busbar-store-memory.
- OWNER: the unix transport is dropped (Q127). Carriers are tcp and stdio.
- OWNER: all 45 accepted differences re-signed for DEV-GREEN (four groups). Q109 signed, Q123
  accepted, Q125 A, Q126 C.
- OWNER: order is CODE → DEV-GREEN → PERF → fixes → DEV-GREEN again; PERF runs on the frozen sha.
- OWNER: two documents only — this spec and the TODO (plus QUESTIONS for owner questions).
- OWNER: predev must stay green; trains carry at most 3 branches ($ alone); a red branch is dropped
  from its train, never the whole train.
- ARCHITECT: FramePiece flags widen u8→u16, size-neutral (status_class u8, _reserved u8, flags u16);
  bits END_OF_FRAME=1, HAS_CODE=2, HAS_RETRY_AFTER=4, STREAM_FAILED=8, FIELDS=16, CONTINUED=32,
  TEXT=64, END_OF_STREAM=128; the unknown-bit probe is 1<<8. One definition per shape: FrameSpan and
  the field-line consts + HOP_BY_HOP live once in `abi/transport/fields.rs`. The host keeps per-stream
  field-line state: an orphan CONTINUED and any ':'-named line FAULT. EncodeIn carries the head words
  (method, target); the connector yields the decoded reply head as a Fields piece.
- ARCHITECT: the store epoch fence is persisted and monotonic; reserve below it is StaleEpoch;
  slice_release is never refused for its epoch; a partial release keeps the slice open; op_id dedupe
  first. Store Pending API: `Step<T>{Ready, Pending{wake_at_ns}}`, a cancel after the write was sent
  is "not applied, or applied and a same-op_id retry answers the identical grants"; resume() None
  under FLAG_RESUME is a FAULT; Pending with wake 0 and nothing in flight is a FAULT; one connection
  per op.
- ARCHITECT: claim_own(op, key, ttl_ms, held: Option<u64>) → Won{epoch, until_ns} | Taken{until_ns};
  label from the calling instance; a kernel ClaimBook over single-use redemption + typed records;
  guard band g = max(1s, ttl/10) — extend only before until_ns − g, claim only after until_ns + g.
- ARCHITECT: a plane cancel is keyed (connection, authenticated principal, correlation); it acts only
  after its own auth; cross-principal or unauthenticated cancels are ignored silently; a duplicate
  correlation follows predev (the first claim keeps the key).
- ARCHITECT: every kind's rows carry the host's one `DeclaredConns` from construction and pass it as
  Bind.conns; the loader serves WRITE_REQUEST/READ_REPLY over it (buffered to END, capped, never
  truncated). Class 0 of dest.judge is the deployment's security section; an unmapped class refuses.
- ARCHITECT: secrets — references resolve in place; only `secret_refs` reach the secrets kind.
  postgres uses ring for HMAC/SHA/PBKDF2; md-5 only for the legacy md5 password method.
- ARCHITECT: the usage floor (Q24/Q28, owner told) is the billing baseline: the plane UNITS class
  flag FLOOR bills like REPORTED; ESTIMATED never bills.

# APPENDIX C — THE PLANE DRIVER AND HOST SERVICES (design, owner-ruled 2026-09-28)


This is a design only. I committed nothing and pushed nothing, and the driver-design worktree has been deleted. It was read against origin/predev `e2a46b791` and the `m1-dispatch` branch at `88283adaf`. Citations: "BB" is `docs/design/BUSBAR-1.6.0.md` (line numbers from that snapshot), "TD" is `1.6.0-TODO.md` KERNEL<>PLUGINS, and "m3" is `m3-inputs.md`. I did not add a SLOT-LOG row because the brief said to commit nothing; the ARCHITECT should record this report. It also covers the coordinator's four additions: (a) the hook projection, (b) health probers, (c) route runs on the existing `busbar-kernel-egress` walk, (d) the webhook receiver as a SERVE op.

### A. The plane driver

**Where it lives.** It goes in `busbar-kernel/src/plane_driver/`. #36 (BB:1437) says `busbar-kernel` itself holds "the loop/registry/teller/sessions", and the crate already depends on `busbar-plugin-loader` (its Cargo.toml line 103).

- The driver is one type, `PlaneUnits`, over the M1 handle `Plugin<Plane>` and the `Dispatcher`.
- It implements the existing `teller::Units` and `RouteAwait` traits. `run_unit_async` and `open_unit` drive it, so no second loop exists. This follows #28's loop unification (BB:1428) and #26's capability-keyed table (the plane's key is registered once).
- Compiled-in and dropped-in planes both arrive as `Plugin<Plane>` from `load_linked` / `load_dropped`, so there is one path (§11.4).
- Each teller step maps to a kernel crate as F20 assigns them: def 3 identity, def 4 scope, def 5 budget, def 6 ledger, def 7 egress, def 10 audit.

**State machine for one unit** (the order §1 sets out, BB:149):

| # | State | Plane op (M1 `submit`) | Kernel side |
|---|---|---|---|
| S0 | ARRIVAL | none | `Units::arrival`: size, rate and source gates |
| S1 | DECODE | `arrive` (pure, Ready, Call class) | Reads `op_class`, `principal_need`, `dialect` and the expected units. A short buffer gets one re-call (M-SB); a second short answer is FAULT (m3 M-SB) |
| S2 | AUTHENTICATE → VERIFY → APPROVE → ADMIT | `project` (new, B.9) when a hook is bound | identity per `principal_need`; scope seals the destinations from the op class's pool; request-stage hooks see the projection (§11.7); budget admits (next list) |
| S2r | REFUSED | `refusal` (`REFUSAL_KERNEL` or `REFUSAL_GATE`) | `audit_refused`, then encode. No hold was opened, so nothing settles |
| S3 | ROUTE (`RouteAwait::route_leg`) | the `on_piece` pump | the kernel-egress walk (next table) |
| S4 | METER | none | the last cumulative units are final. Only `UNITS_REPORTED` bills (abi/plane rule 2) |
| S5 | AUDIT | none | the one fixed record (§1, BB:186) |
| S6 | EXIT | none | settle: one sealed line per unit (§7, BB:557). A late arm files under the arrival window (TD step 14) |
| SX | CANCEL | lifecycle `cancel` (ticketless, may not pend) | see the money seam below |

**Money seam at ADMIT** (§7 Budgets, BB:570):
- `admission: exact` refuses only a budget that is already exhausted.
- `admission: estimate` checks `arrive`'s expected units × the highest price among the sealed destinations.
- The hold is sized per TD step 17 and a concurrency lease is drawn. Kernel-verb, tick and handshake origins draw no lease (BB:198).

**S3, the pump.** It runs on the M1 worker that owns the unit's ticket:
1. **Caller body.** `SHAPE_WHOLE` pushes one `FROM_CALLER` piece with `PIECE_LAST`. `SHAPE_PIECEWISE` pushes each piece as it arrives.
2. **Attempt start.** The walk is `busbar_kernel_egress::walk`, the existing `EgressUnit` already built at `crates/busbar/src/root/kernel.rs:1308`; nothing new is written (coordinator c).
   - It picks a member and consults the breaker, allow-list and pin.
   - The driver pushes an ATTEMPT piece: `from = FROM_KERNEL` with the new `OnPieceIn.attempt` (member index) and `attempt_no` fields (B.10).
   - The plane answers with `EMIT_TO_FAR_END`: fields (verb and target first, passed opaque to the framer) plus body bytes. This is the walk's `encode_egress` port.
   - ~~The kernel makes the one per-request auth call (§6.4) and sends through the connector (§5 table, rows 2–8).~~ The transport calls the attempt binding's auth at its points and sends (THE DESIGN §6). SUPERSEDED 2026-09-30 by THE DESIGN §6, "Auth points and guest lists".
3. **Far-end pieces.** Each is pushed as `FROM_FAR_END` with `PIECE_HAS_STATUS`. The plane's `emitted` bytes go to the caller; this is the walk's `decode_response` port.
   - The breaker disposition comes from the walk's status table (TD step 24).
   - The plane can also give a body-level verdict in `OnPieceOut.verdict`, which is the renamed `_reserved` field (B.10).
   - The walk fails over only before the first byte reaches the caller (the rule in its own module doc). Exhaustion goes to its existing terminals (shed, spill, wait).
4. **Backpressure.** READY with `more = 1` means flush, await writable, then call again with an empty piece (abi/plane doc; P4: `more = 1` with `emitted = 0` is FAULT).
5. **Units.** Every READY answer carries cumulative units, which become a running checkpoint (crash-safe, never a ledger line; §7, TD step 15). If a checkpoint dries the budget:
   - `on_exhaustion: cut-stream` means the driver calls `refusal` for the in-stream error frame, then settles one Abort line (§7 "A cut is told", BB:576).
   - `finish-unit` means the unit runs to its end.
6. **Records.** `RecordWrite`s go to the store's plane-record slots as coalesced write-behind batches with one `op_id` per batch (§11.11 H4, m3 store rulings).
7. **Other outcomes.**
   - `EMIT_DONE` goes to S4.
   - PENDING waits for the wake (latched, generation-checked; H2), with the deadline in the Stream class.
   - FAULT becomes `Ended` failed. The caller gets `refusal` bytes if that op is healthy, otherwise the kernel's generic failure.

**Cancel** (client drop, deadline, reload). The M1 dispatcher calls `cancel` and carries its disposition up (M1 rulings). The driver then:
1. bills using `cancel_bills_reported_units(disposition, streamed)` (abi/plane, the four 1.5.5 rules; §11.11 M3 parity, BB:892; F13);
2. releases the budget hold as a separate act, never folded into billing (rule 4);
3. posts the end through `RouteAwait::abandoned` so it is not dropped (teller.rs, item 99).

**Duplex sessions** (`INGRESS_DUPLEX_SESSION`, Part 4 Axis 1; #23 BB:1419):
- `open_unit` runs S0–S2 and admits at open. The session then pumps pieces in both directions on two tickets, one per side (the P2 rule applied to planes).
- **Unsolicited output** (the plane pushing a notification or a nested request): the plane wakes the session's driver ticket (`Dispatcher::driver`). The driver then calls `on_piece` with `from = FROM_KERNEL`, an empty piece and no attempt, to collect it (B.10).
- **Per-turn metering:** cumulative units feed the kernel's `SessionAccount` (`plane_host/session_meter.rs`). Each turn is a checkpoint with a `Live` / `MustClose` verdict; `MustClose` is a cut. The session end writes one sealed line.
- Hooks inside a session use `hook.call` (B.6).
- The stdio carrier's frames are pumped by the host; the plane never touches the fd (Part 3 §3).

**Streams.** A response-stream is S3 with many `FROM_FAR_END` pieces. A non-billed listen stream is admission-governed and zero-metered (#28).

### B. Host services

**One mechanism for all of them.** Every new service reuses the connector's call shape unchanged (`abi/host/conn/connector.rs`):
- `ServiceFn(ctx, in, *mut ServiceOut)`, where each `in` leads with `ServiceHead{size, op, CompletionHandle}`.
- PENDING wakes the handle. On resume the plugin re-issues the same handle and gets the stored result; the host never runs a service twice.
- A call made with `Ticket::NONE` may not pend.
- **M-SB for every service:** a result goes into host buffers named in the `in` (ptr + cap). The `out` states written and needed. A short answer is FAILED with needed > cap and nothing applied or written. The re-call reads the stored result and is side-effect-free (P1). A second short answer is FAULT.
- Validators sit beside each shape as `check_<op>` (m3 "WITH THE SHAPE").

**Layout.**
- One new file, `abi/host/service.rs`, holds the shared head and out.
- One new table, `HostSlots`, is appended to `HostTables` after `conns` (`size`-guarded; R9 means an append bumps the version, but pre-release appends are guarded by the layout golden; §10).
- Op names are grouped by family. Every name passes the neutrality witness (BB:1907): no llm, mcp, a2a, tool, agent, sampling, task, server, card, round or prompt.

**B.1 Step-3 services that need no new shape:**

| TD step 3 item | Maps to |
|---|---|
| conn | the landed connector table (m3 "HOST CONNECTOR: ONE DESIGN") |
| `govern_admit(expected_units)` | `ArriveOut` expected units (§5 delivery, BB:437) |
| `meter_report` | cumulative units on every `on_piece` answer (§11.11, BB:812) |
| tick | lifecycle `tick`, driven by the kernel's one clock (§1, BB:157). TickIn carries `now_ns` |
| snapshot | the export kind's `ScrapeIn` whole-snapshot (m3 H5) |
| `route.*` | subsumed by the pushed ATTEMPT piece plus `verdict`. This departs from the "asks `route.next`" wording in §6.1 (BB:503), so it is D1 |
| journal writes | `on_piece` `RecordWrite` |

**B.2 New services:**

| Service op | In (after ServiceHead) | Out | Class | May pend | Covers |
|---|---|---|---|---|---|
| `clock.now` | none | `value` = wall ns, `len` = mono ns | Call | no | step-3 clock |
| `records.get` | `kind: u32` (tail index), `key: AbiStr`, `buf/cap` | `len` / needed | Call | yes (store may pend) | request-time plane-record reads; journal reads |
| `records.list` | `kind`, `parent`, `after_seq`, `rows_buf/cap`, `arena/cap` | rows + arena, multi-dimension M-SB | Call | yes | same |
| `records.claim` | `kind`, `key`, `ttl_s` | `value`: 1 FIRST / 2 SEEN | Call | yes | one-time approval redeem, webhook replay refusal |
| `dest.judge` | `target: AbiStr`, `egress_class` | `value`: 0 ALLOW / reason code | Call | no | argument-embedded URLs (F6). The same pure judge that runs before a dial (Q84 list) |
| `sign` | `payload: Blob` | `sig_buf/cap`, `kid_buf/cap` | Call | no | card and artifact signing (below) |
| `unit.nest` | `claim: u32`, `fields`, `body: Blob`, `reply_buf/cap`, `fields_buf/cap`, `arena/cap` | status, written / needed | Stream | yes | nested dispatch (below) |
| `work.open` / `work.find` / `work.settle` / `work.resume` | handle key plus a record ref | `value` = handle | Call | yes | durable async work (below) |
| `trust.sight` / `trust.due` / `trust.redeem` | subject key, catalogue hash | verdict NEW / SAME / DRIFTED / QUARANTINED; due list | Call | yes | trust lifecycle F5 (below) |
| `hook.call` | `stage`, projection struct (B.9's `ProjectOut`) | verdict (hook-kind shape) | Call (off-worker lane, R1) | yes | in-session gates (§2 table) |

Row notes:
- **`records.*`** are scoped to the calling instance's `record_kinds` and forward to the store v3 plane-record slots, which already follow M-SB. `records.claim` needs a put-if-absent store slot (D5).
- **`sign`** signs under the plane's Statement `signing_domain` / `signing_kid_prefix` with `Kernel::sign_token`. The plane assembles the envelope itself. It is refused if the tail declares no signing domain.
- **`unit.nest`** runs a child unit through the driver:
  - `Run.parent` is the caller's hold cell; the child accrues against the parent (teller `at_parent_exit`, Q71(4)).
  - The principal and audit correlation are the parent's, and depth is capped (Part 4 BB:1891; RR7 at BB:1629).
  - The kernel routes by claim. It never learns the target is another plane.
  - The reply is buffered whole in 1.6.0; the child's live stream is a later append.
- **`work.*`** are kernel-owned (§1 BB:195: never evicted; admission refuses at the bound; the sweep runs on submit). `work.find` is the anti-enumeration scoped lookup: every denial answers identically (§10 BB:660). The body lives in plane records. A continuation runs as a child unit whose parent has exited, so it files under the late-arm rules (TD step 14; Part 4 Axis 2).
- **`trust.*`** are kernel-owned (F5). The plane reports hashes and the kernel judges them. `trust.due` lists the subjects the kernel's tick has marked for reverify; the plane refetches through conn and sights them again. Pinning and demotion stay kernel state; today's logic in `plane_host/trust.rs` moves behind these ops. Approval redemption is `records.claim`.

**B.3 The fold agents' gaps, mapped:**
1. Request-time record reads: `records.get` / `records.list`.
2. Work handles: `work.*`.
3. Trust lifecycle: `trust.*`.
4. Signing: `sign`.
5. Plane-originated hops outside the route (fetch, push delivery): existing conn. The plane declares an outbound Need of class `open-web` in its tail and uses ESTABLISH with its target (§5 BB:423/445, F-rulings); metadata hosts are refused before the dial. The dial is pinned to the addresses `dest.judge` judged through `EstablishIn.within` (the dial-pin appends, Axis 3, ARCHITECT DEST-PIN 2026-10-01).
6. Inbound webhook receiver: a plane SERVE op (d), covered in B.9.
7. Tick (reverify, retry): lifecycle `tick` with `next_tick_ns`, plus `trust.due`.
8. `{tool, arguments}` projection: the `project` op (B.9).
9. Nested dispatch: `unit.nest`.
10. Approval / elicitation: the elicitation request is plane traffic to the caller. On a duplex session it is an unsolicited emit plus a `FROM_CALLER` answer; across separate HTTP arrivals it is correlated with `work.*`. Approval redemption is `records.claim`. No separate service.
11. Argument-embedded URL judging: `dest.judge`, called where it is called today (F6). Under `DEST_RESOLVE` it also writes the addresses it judged (`DestJudgeIn.into`), the set item 5's dial is pinned to.
12. Auth `exchange()` (F7): no plane service. It is an outbound style whose one per-request call (§6.4) runs `exchange` inside the auth plugin, using the caller's verified credential (the caller-credential precedent) and the provider's target as the audience (TD step 39). The plane never sees the token (§6 trust boundary).
13. Per-session metering: the driver's session path (A).
14. **Health probers (b, F23).** A plane declares tail flag `TAIL_PROBES`, a new vocabulary bit with no layout change. kernel-breaker's tick starts a probe unit: kernel origin, no lease, zero-billed (BB:198), pinned to one member. The driver calls `arrive` with `claim = CLAIM_PROBE` (`u32::MAX`), then pushes the ATTEMPT piece, and the plane emits the probe request. The walk's status table classifies the result, recording nothing on a client-fault class, as in 1.5.5 `health.rs`.
15. **io.\*** is the transport kind's only: register, poll_ready, clear_ready, deregister (§2 table). It is not a plane service; its shape is TD step 19's.

**B.9 Plane-side additions (coordinator a and d; Part 3 §9, F22):**
- **`project`**, a new kind op (`LIFECYCLE_SLOTS + 6`, pure, Call class).
  - In: `claim`, fields, body.
  - Out: the hook `RequestView` plane-derived fields (`pool`, `ingress_dialect`, `message_count`, `total_chars`, `max_tokens`, `flags`, signals) with strings in the arena, plus an optional projected body span, which is `{tool, arguments}` for the mcp and a2a planes. The rule is multi-dimension M-SB.
  - The kernel fills the stage fields from the walk: `at`, `model` / `provider`, `attempt_number`, `remaining_candidates`, `previous_failure`, `outcome`, `status`, and candidates with `cost_per_mtok` taken from the card. The plane stays pricing-blind (#43).
  - The 178 v1.5.5 hook tests run verbatim against the driver (M4 HOOK-PARITY). An unexpressible test means the shape is wrong (#85).
- **`AdminRoute.flags`**, appended with `ROUTE_PUBLIC`. SERVE then serves an un-admin'd public route: the arrival gate and audit still run, it is zero-metered, and it is off unless configured (§10 stateful-handles-webhook).
  - The signature check cannot run in the plane, because a plane never receives secret bytes (§6 trust boundary). The route is a guest-list line whose auth is that style (THE DESIGN §6), and an auth plugin verifies the signature over the signed bytes. This is the inbound body-aware verify the review moved into auth plugins; replay refusal uses `records.claim`.
  - 1.5.5 default bytes are preserved: with no secret configured, nothing mounts.

**B.10 `abi/plane` appends** (plane ABI is 1; pre-release, guarded by the layout golden; D1):
- `OnPieceIn.attempt: u32` and `attempt_no: u32`
- `FROM_KERNEL = 2`
- `OnPieceOut._reserved` renamed to `verdict` (0 none / 1 ok / 2 retry / 3 hard)
- `CLAIM_PROBE`, `TAIL_PROBES`
- the `project` op
- `AdminRoute.flags`
- a per-record-kind chain framing list in the tail (LengthPrefixed or PipeSeparated, plus `digests_scope`), so the host reproduces Part 3 §5's three framings

### C. Build order (S/M/L, arrows are dependencies)

| Slot | Size | Depends on | Content |
|---|---|---|---|
| G0 | S | none | owner and ARCHITECT sign-off on D1–D6 |
| P1 | S | G0 | the B.10 appends, `check_*` validators, a RED test per rule (H6), C header regenerated |
| H1 | M | G0, M1 landed | `abi/host/service.rs`, `HostSlots` in `HostTables`, `clock.now`, `dest.judge`; a kind-neutral double; the M-SB re-call RED |
| K1 | L | P1, H1 | `PlaneUnits` over `Plugin<Plane>`: S0–S2r, the S3 pump against a double far end, backpressure, M-SB re-call, cancel disposition, `abandoned`. Proof: zero plane→host calls per chunk, crossing under 1 µs (§11.9) |
| K2 | M | K1 | S3 bound to the kernel-egress walk (attempt piece, verdict, failover before first byte, exhaustion terminals). It uses the walk's current attempt port until connector, http and auth-call (TD 18–22) land, then re-points |
| K3 $ | M | K1, TD 13–17 | hold at admit (exact / estimate), checkpoints, cut + Abort line, cancel-billing rule, separate refund. Lands alone; `billing\|ledger\|teller` families; kill -9 RED |
| K4 | S | K1, M3-store v3 | fixed audit record; RecordWrite batches; `records.get` / `records.list` |
| K5 | M | K2, M3-hook | `project` op and stage taps; `hook.call`; the 178 1.5.5 hook tests verbatim |
| MCP-1 $ | L | K2–K5, FOLD-MCP phase A | mcp `streamable-http` through the driver, flipped by composition (#28 seam 2). Oracle: `mcp\|streamable-http` 456 cells byte-identical, plus plane conformance, compiled-in and dropped-in |
| K6 $ | M | K3 | duplex sessions: `open_unit`, two tickets, `FROM_KERNEL` pump, SessionAccount, one sealed line (#23) |
| MCP-2 | M | MCP-1, K6 | mcp stdio: `mcp\|stdio` 456 cells |
| H2 | M | H1, K4 | `records.claim`, `sign`, `trust.*` plus kernel trust state behind them |
| H3 | M | K3 | `unit.nest` (depth cap, parent accrual), `work.*` (bound, scoped lookup, late arm) |
| MCP-3 | M | MCP-2, H2, H3 | mcp sampling, sightings, reverify, elicitation; the mcp family fully green |
| K7 | S | K2 | the probe unit (F23) |
| A2A | L | H2, H3, MCP-3 | work handles, card signing, push delivery through conn; SPEC a2a |
| LLM | L | K2, K5, K7 | walk flip (c); webhook SERVE and the inbound auth style; probes; F19 legacy loop retired |
| STRM / DEC | M each | K6, K3 | streaming (key stays `voice`, F10) and decisions on the driver |
| DEL | M | all | delete the gauntlet riders, the substrate loop and the hot host vtable (TD 36) |

The critical path to the first end-to-end plane is G0 → P1 → H1 → K1 → K2 → K3 → K4 → K5 → MCP-1. MCP-1 does not wait on TD 18–22, because K2 uses the walk's existing attempt port inside the coexistence window (TD steps 23–36).

### D. Owner decisions needed (the ABI is owner-locked, §11)

- **D1. The plane ABI appends in B.10**, especially the pushed ATTEMPT piece replacing `route.next` / `route.settle` as host services. It departs from the wording of §6.1 and the §2 table, but keeps zero host calls per chunk and reuses the built walk (c). One more question: is the plane ABI's first release allowed these appends without a version bump (§10 / R9)?
- **D2. The new `abi/host` surface:** `HostSlots` and the families clock, records, dest, sign, unit, work, trust, hook. It follows the connector's call shape.
- **D3. Session money under §11.** Under #28 ruling (3), Option C-on-A, the plane kept its own reserve, and Option B (the kernel owns settlement) was rejected. A plugin cannot hold money across the ABI (§7 "plane reports; kernel writes"; #43), so I propose the kernel's `SessionAccount`, driven by `on_piece` units, replaces the plane-side reserve. #28(3) needs re-ruling.
- **D4. The webhook signature verify moves from the llm plane to an auth-kind inbound style**, because a plane never receives secret bytes (§6). Bytes are preserved and the default is off.
- **D5. `records.claim` needs a put-if-absent store v3 slot with a TTL.** This is a store ABI append.
- **D6. The 1.6.0 limits:** `unit.nest` returns a whole buffered reply; there is one live attempt per unit (no hedging); `project` is called once per unit and the stage fields are kernel-filled.

**Assumptions I made:**
- Estimated units never bill on any end, not only on cancel. This matches 1.5.5 billing only provider-reported usage.
- In-session hook gates use the `hook.call` service rather than a pushed verdict piece.

**Files that ground this:**
- `crates/busbar-contract/src/abi/plane/mod.rs`
- `crates/busbar-contract/src/abi/host/conn/connector.rs`
- `crates/busbar-contract/src/abi/mechanism/ticket.rs` (`HostTables`)
- `crates/busbar-kernel/src/teller.rs` (`Units`, `RouteAwait`, `run_unit`, `open_unit`)
- `crates/busbar-kernel-egress/src/lib.rs` (the walk)
- `crates/busbar/src/root/kernel.rs:1308`
- `crates/busbar-kernel/src/plane_host/{session_meter,trust}.rs`
- the m1-dispatch branch's `crates/plugin-loader/src/dispatch/{mod,worker,kinds/plane}.rs`

**Agents:** none spawned. I did the reading and design directly, since this was judgment work over a bounded set of files.

# APPENDIX D — THE BOOT LOOP (ARCHITECT-ruled 2026-09-27)


Cell: busbar × plugin-tooling. Measured 190, ratchet 168, target ~12. Q81 is closed as "drained, not re-armed".
The gate counts crate-path spellings busbar[-_ ]?plugin[-_ ]?(loader|pack|example) in all .rs/.toml under crates/busbar (matrix.rs:230-305).

### Root cause
1. No boot stage owns loading: 6 load/scan sites, and linked rows take 4 different paths (breaks #2 rule (1)).
2. The contract has no host-side face, so registries, dispatch and replies are typed by loader types.
3. The loader re-export shims (plugin-loader/src/lib.rs:61-101) invite spelling contract types via the loader.
4. There is no test fixture: 73 lines of tarball-packaging boilerplate are copied into about 14 files.

### Target
- crates/busbar/src/root/boot.rs is the ONLY src file naming the loader.
  - stage 0: Plan (the plugins: block);
  - stage 1: load: sweep, then ONE busbar_plugin_loader::load(LoadRequest{linked rows, dir, policy, HostServices});
  - stage 2: register: planes→kernel, exports/diagnostics/stores(default)→kernel axes;
  - stage 3: seal(TransportSettings) → BootRegistry;
  - plus inventory() for --plugins.
  main.rs calls root::boot::run then seal.
- Contract owns the host-side types:
  - abi::hot: HotPlane, ServedHot, ReplyStream, HotReply, RequestHead, MAX_PLANE_REPLY_LEN;
  - abi::cold::export: EgressCarrier, EgressPolicy;
  - transport::TransportRow;
  - LinkedRow enum.
  The loader implements them. The HOT adapter (linked.rs:405-872) moves to busbar_kernel::plane::hot on Arc<dyn HotPlane>.
- Tests: one fixture, tests/common/plugins.rs (pack(kind,name,lib,publisher), boot_with(dir)). Loader proofs go to plugin-loader conformance tests; sink-specific proofs go to the sink repos.
- Expected: Cargo 1, boot.rs 3, fixture 4–6, about 12 in total.

### Rulings
R1. APPROVED as designed.
R2. Step 3 (re-point contract-owned types from the loader path to busbar_contract::abi::*) is an OWNERSHIP FIX, not a matcher dodge, ONLY IF the same commit deletes the loader re-export shims, so the loader path can no longer compile.
   An alias, a glob, `use ... as`, or a shim kept alive = revert.
R3. Fetch order is unchanged in this migration. plugins.fetch stays after the root scan, and the boot lines stay byte-identical to 1.5.5 (boot_lines_neutrality). The "fetched plugin unseen on first boot" behaviour is recorded as a separate question and not changed here.
R4. Kernel reload rescans (preflight.rs:358) stay in the busbar-kernel × plugin-tooling cell; that cell is not part of this work.
R5. Step 6 (move the HOT adapter, money-adjacent: with_plane_door meters and bills) and step 10 (MONEY: store seams) each go alone, with the oracle including the shadow store-persist cells.
R6. Sequencing: steps 1–5 start now. Steps 6–11 wait on:
   - the plane and transport KIND-DESIGN rulings (the HotPlane trait shape; TransportRow vs DOOR-TRANSPORT's Connection);
   - STORE-DEFAULT and AUTH-ROW landing their linked.rs edits.
   Step 9 rebases on DOOR-TRANSPORT's final Connection commit.
R7. The claims for dropped-in planes (TODO #240, invisible to the boot overlap check) are routed to the plane KIND-DESIGN, not solved here. Resolved by THE DESIGN §6 step 3 (2026-09-30).

### Steps (delta from 190)
1. Test fixture; migrate the 14 packaging copies: −~68.
2. Move loader-proving tests to plugin-loader or plugin conformance suites; drop the example-plane dev-dep if unused: −~32.
3. Point contract-owned types at busbar_contract::abi::* AND delete the loader re-export shims: −~20.
4. EgressCarrier and EgressPolicy to contract (contract re-arm in its own commit): −~12.
5. ReplyStream, HotReply and RequestHead to contract (re-arm in its own commit): −~10.
6. HotPlane trait, HOT adapter to the kernel. MONEY-ADJACENT: its own commit: −~3.
7. busbar_plugin_loader::load(LoadRequest): ±0.
8. boot.rs: one load call; linked exports as LinkedRow; delete the test-only dropped_planes; fold sweep and inventory: −~15.
9. TransportRow; collapse registry.rs Row: −2.
10. MONEY: the kernel hands over the store seams (main.rs:484/572, migration.rs:59, keyset.rs:28). Alone, with the shadow oracle: −7.
11. --write-standing, 168 → ~12; close Q81.

# APPENDIX E — TRANSPORT / BINDING COMPATIBILITY MATRIX (2026-09-29)

(Note 2026-09-30: unix is dropped (Q127); gRPC is its own transport `busbar-transport-grpc`, OWNER 2026-09-29.)

# busbar transport/binding compatibility matrix

Compiled 2026-09-29 against `origin/predev` HEAD (`c6556ddd2`). Sources: official specs (cited inline)
and repo inspection via `git -C /Users/matthew/Developer/GetBusbar/busbar show origin/predev:<path>` /
`git grep`. Local working notes: `docs/design/BUSBAR-1.6.0.md` Part 2,
`docs/design/1.6.0-QUESTIONS.md`, `docs/design/1.6.0-TODO.md`,
`Appendix B`.

Legend — **busbar today**: yes / partial / no. **size**: S/M/L. **transport kind**: which of
busbar's transport doors (`tcp`, `stdio`, `http` h1/h2/h2c, `ws`, `grpc`) carries it, or **NEW** if it
needs a kind busbar doesn't have.

---

### 1. A2A (Agent2Agent) plane — `busbar-plane-a2a` / `busbar-a2a`

Spec: A2A v1.0.0, https://a2a-protocol.org/v1.0.0/specification/ (canonical proto:
`spec/a2a.proto`; prior versions v0.3.0/v0.2.6/v0.1.0 also on that site; project now under the
Linux Foundation Agentic AI Foundation, ~2026-08-27).

| Protocol | Binding (official) | Direction | Spec status | busbar today | Gap | Size | Transport kind |
|---|---|---|---|---|---|---|---|
| A2A | JSON-RPC 2.0 over HTTP(S) (§9) | server + client | one of three MUST be offered (§8.1/§8.3.1); no fixed minimum count | **yes** — `busbar-a2a/src/a2a/jsonrpc.rs`, `rpcerror.rs` | — | — | http h1/h2 |
| A2A | HTTP+JSON/REST (§11), `application/a2a+json` | server + client | optional (see above) | **yes** — `busbar-a2a/src/a2a/rest.rs` | — | — | http h1/h2 |
| A2A | gRPC over HTTP/2+TLS (§10), from `a2a.proto` | server + client (both directions) | optional (see above) | **partial** — `busbar-a2a/src/a2a/grpc.rs` implements the service, but it currently rides inside `busbar-transport-http`'s folded-in gRPC module, not a standalone transport door. Owner ruling 2026-09-29 (m3-inputs.md:395-398): *"A2A over gRPC is supported in 1.6.0, BOTH directions"*; reverses an earlier ARCHITECT "gRPC is not a transport" call; new crate `busbar-transport-grpc` (layered on HTTP/2, "like ws on h1") is approved and in flight, owner's own estimate: *"minimal change... 1 new transport and that's basically it"* | **S** (owner-scoped, in flight — slot GRPC-DOOR) | http h2/h2c today → dedicated `grpc` door planned |
| A2A | SSE streaming for JSON-RPC/REST (§3.5.1, §5.3, §11.7), gated by `AgentCard.capabilities.streaming` | server + client | optional, capability-gated | **yes** — `busbar-a2a/src/sse.rs` used by both JSON-RPC and REST streaming legs | — | — | http (SSE over h1/h2) |
| A2A | gRPC server-streaming (§10.7) | server + client | optional, capability-gated | tracks gRPC binding status above | same as gRPC row | S | http h2 → `grpc` door |
| A2A | Push notifications via webhook (§3.5.3, §13.2), gated by `AgentCard.capabilities.pushNotifications` | server (delivers), client (registers) | optional | **partial** — registration/config CRUD implemented (`pushnotify.rs`) with resolve-then-pin SSRF/DNS-rebinding guard; `pushdeliver.rs`/`pushback.rs` exist but end-to-end delivery is "not yet driven in production" per repo inspection | wire the delivery path end-to-end | **S–M** | http (outbound client to customer webhook) |
| A2A | Agent Card discovery, `/.well-known/agent-card.json` (§8.2, §14.3; renamed from `agent.json` at spec v0.3) | server (serves) | MUST | **yes** — `busbar-a2a/src/a2a/card.rs`: canonical `WELL_KNOWN_CARD_PATH` plus legacy `agent.json` tolerated on fetch | — | — | http |
| A2A | Auth: API key / HTTP auth / OAuth2 / OIDC / mTLS scheme objects (§4.5, §7) | both | server MUST authenticate per declared scheme | **yes** — JWS/Ed25519 card-signature verification (`jws.rs`), pinned/mutual TLS with SPKI-pin fallback (`transport.rs`, `key_info.rs`), RFC 9728 protected-resource metadata served | — | — | http (TLS) |

**A2A-over-WS**: deliberately **not built** — owner-ruled 2026-09-27 (Q89, `docs/design/1.6.0-QUESTIONS.md:139`): *"MCP and A2A serve only the transports their published specs define; no ws binding is built."* Not a gap — spec fidelity by design; the A2A spec has no WS binding anyway.

---

### 2. MCP (Model Context Protocol) plane — `busbar-mcp` / `busbar-plane-mcp`

Spec: https://modelcontextprotocol.io/specification/ — revision history `2024-11-05` →
`2025-03-26` → `2025-06-18` → `2025-11-25` → **`2026-07-28`** (current as of 2026-09-29, confirmed
live at `/specification/2026-07-28`). Authorization: `/specification/<rev>/basic/authorization`.

| Protocol | Binding (official) | Direction | Spec status | busbar today | Gap | Size | Transport kind |
|---|---|---|---|---|---|---|---|
| MCP | stdio (newline-delimited JSON-RPC) | server + client | SHOULD support when possible; unchanged across all revisions | **yes**, both directions — `mcp/stdio_serve.rs` (inbound), `mcp/client/stdio.rs` (outbound, no-shell/absolute-path-only/cleared-env child spawn) | — | — | stdio |
| MCP | Streamable HTTP, **`2026-07-28`** shape: POST-only endpoint, no sessions, no `initialize` handshake, no `Mcp-Session-Id`, no GET stream/resumability (SEP-2243/SEP-2575) | server + client | current spec's MUST-support HTTP transport | **yes** — `busbar-mcp/src/mcp/mod.rs` targets exactly `2026-07-28` stateless model; SSE retained only as a response *content-type* on POST (`mcp/sse.rs`), negotiated via `Accept` | — | — | http h1/h2 |
| MCP | Streamable HTTP, **`2025-03-26`/`2025-06-18`/`2025-11-25`** shape: `Mcp-Session-Id` sessions, GET stream for server-initiated messages, SSE resumability via `Last-Event-ID` | server + client | was the current/MUST HTTP transport for ~2.5 years; still what the large majority of *already-deployed* MCP servers/clients speak as of Sept 2026, since `2026-07-28` only just shipped | **no** — busbar jumped straight to `2026-07-28`; no session header, no GET stream, no `Last-Event-ID` resumability anywhere in `busbar-mcp` | **highest-value interop gap in this matrix**: busbar cannot talk session-based Streamable HTTP to the installed base of MCP servers/clients built against 2025-xx revisions | **M** | http h1/h2 (needs GET-stream + session-header + resumability support added back, likely as a compat shim) |
| MCP | Deprecated HTTP+SSE (`2024-11-05`): two-endpoint SSE-stream + POST model | server + client | deprecated since `2025-03-26`; formally "Deprecated"/removal-eligible as of `2026-07-28`'s feature-lifecycle policy; SHOULD NOT for new implementations, but spec still documents a compat fallback for old peers | **no** — dropped per revision jump | legacy servers/clients on `2024-11-05` unreachable | **M** (bundled with the row above if both are tackled together) | http h1 |
| MCP | WebSocket | — | **never officially defined** in any MCP revision (only community/unmerged proposals, e.g. SEP-1287, issue #3339) | **no** (deliberate) | none — not a gap, spec has no WS binding | — | n/a |
| MCP | Authorization: OAuth 2.1, RFC 8707 resource indicators, RFC 9728 protected-resource metadata, RFC 8414/OIDC discovery | server (resource server) | required when HTTP-based auth is used | **yes** — busbar acts as resource server: 401 + `WWW-Authenticate` naming the RFC 9728 doc, `aud` check enforces RFC 8707 against operator-configured canonical URI; does not itself act as AS for `mcp:` (verify-only); separate in-core `oauth_as` plane can mint RFC 9068 `at+jwt` tokens when configured | Dynamic Client Registration / Client-ID-Metadata-Document flows not confirmed present | S (if needed) | http (TLS) |

---

### 3. LLM plane — `busbar-llm` / `busbar-plane-llm` (six dialects, one IR)

| Provider / API | Official transport | Direction | Spec status | busbar today | Gap | Size | Transport kind |
|---|---|---|---|---|---|---|---|
| Anthropic Messages (`api.anthropic.com/v1/messages`, `anthropic-version: 2023-06-01`) | HTTP POST + SSE | client (busbar calls out) | current, only API | **yes** — `codec/anthropic/` | — | — | http + SSE |
| OpenAI Chat Completions | HTTP POST + SSE | client | not deprecated, industry-standard fallback | **yes** — `codec/openai_chat/` | — | — | http + SSE |
| OpenAI Responses API | HTTP POST + SSE; async/background jobs deliver via webhook | client (+ inbound webhook receiver) | current recommended unified API (since Mar 2025) | **yes** — `codec/openai_responses/`; webhook receiver `busbar-llm/src/openai_responses_webhook.rs` (Standard Webhooks HMAC-SHA256), off by default | — | — | http + SSE; http (inbound webhook) |
| Google Gemini `generateContent`/`streamGenerateContent` | HTTP POST + SSE (`alt=sse`) | client | current | **yes** — `codec/gemini/` (own `framer.rs`) | — | — | http + SSE |
| AWS Bedrock Converse/ConverseStream | HTTP POST (SigV4) + AWS event-stream binary framing (`application/vnd.amazon.eventstream`), not SSE | client | current unified Bedrock API | **yes** — `codec/bedrock/`, `codec/eventstream.rs` (CRC-32 checked) | — | — | http (event-stream framing) |
| AWS Bedrock InvokeModel / InvokeModelWithResponseStream (older, model-native payloads) | HTTP POST (SigV4) + event-stream | client | still current, some model families still require raw InvokeModel shape | **no evidence found** — only Converse dialect present | model-specific raw-payload access if a customer needs it | S (if needed) | http (event-stream framing) |
| Cohere v2 (not requested, found anyway) | HTTP POST + SSE | client | current | **yes** — `codec/cohere/` (bonus dialect) | — | — | http + SSE |
| OpenAI Realtime / Gemini Live | WebSocket (see §4 — these are **not** LLM-plane dialects) | — | — | handled in streaming plane, not here | — | — | — |

---

### 4. Streaming / realtime voice plane — `busbar-plane-streaming` / `busbar-voice`

| Protocol | Official transport | Direction | Spec status | busbar today | Gap | Size | Transport kind |
|---|---|---|---|---|---|---|---|
| OpenAI Realtime | WebSocket, `wss://api.openai.com/v1/realtime?model=…` | client (egress) | GA | **yes** — `claims.rs` `Dialect::OpenaiRealtime`, "WebSocket, PCM16, tool calls, full duplex" | — | — | ws |
| OpenAI Realtime | WebRTC: ephemeral key via `POST /v1/realtime/client_secrets` → SDP exchange via `POST /v1/realtime/calls`, audio over SRTP, events over `RTCDataChannel` | client (busbar terminates WebRTC for browser clients per design #45) | GA, recommended for browser/mobile | **partial** — signaling/minting exists (`busbar-voice/src/topology/webrtc.rs`, `minter_https.rs`) but claims.rs states *"no codec surface for the RTP media plane exists... a browser-sideband ferry over the same JSON event vocabulary rather than a distinct wire format"* | RTP/SRTP media-plane codec surface | **L** | **NEW** — WebRTC/SRTP is not one of busbar's existing kinds (tcp/stdio/http/ws/grpc); needs an ICE/DTLS-SRTP media stack (e.g. `webrtc-rs`) alongside the existing signaling path |
| OpenAI Realtime | SIP: `sip:$PROJECT@sip.api.openai.com;transport=tls`, webhook-driven call accept/reject/refer, OpenAI terminates SIP/RTP itself | — | GA (native since Aug 2025) | **no** — `docs/design/BUSBAR-1.6.0.md` #45 currently reads *"raw SIP is not carried."* **Flagged, not assumed**: this is a standing owner/ARCHITECT decision point, not a technical conclusion of this research pass — do not treat it as settled either way. Customers can reach OpenAI's SIP surface indirectly today via Twilio SIP trunk → Twilio Media Streams → busbar's `ws` door, without busbar terminating SIP itself | native SIP trunking, if the owner decides busbar should terminate SIP directly | **L** if built directly | **NEW** — SIP signaling + RTP termination; scope is an open owner decision, see #45 |
| Google Gemini Live (`BidiGenerateContent`) | WebSocket, `wss://generativelanguage.googleapis.com/ws/...BidiGenerateContent` (no WebRTC variant in official docs) | client (egress) | current, only transport Google documents | **yes** — `claims.rs` `Dialect::GeminiLive` | — | — | ws |
| Twilio Media Streams | WebSocket fork of a SIP/PSTN call via TwiML `<Stream>`, JSON events (`start`/`media`/`stop`/`mark`/`dtmf`), µ-law 8kHz audio | server (inbound from Twilio) | current | **partial** — codec/dialect complete (`claims.rs` `Dialect::TwilioMediaStreams`, `ulaw.rs`, `topology/twilio.rs`) but **no transport-registry crate**: repo inspection states *"the telephony transport has no crate in the tree... `twilio-media` is one of the six that do not [exist]"* | register/wire the WS-carried telephony transport door | **S** (codec done, just needs the transport claim/wiring) | ws (once wired) |
| One-shot transcribe / TTS | HTTP request/response | client | n/a (not a streaming spec) | **yes** — `Dialect::OneShotTranscribe`/`OneShotTts` | — | — | http |

---

### 5. Transport-crate inventory vs. design roster

`docs/design/BUSBAR-1.6.0.md` (§9 crates table, decision #3) specifies transport roster
`tcp, stdio, http, ws, grpc`. As of `origin/predev`:

| Transport kind | Crate | Status |
|---|---|---|
| `tcp` | `crates/busbar-transport-tcp` | yes — base byte-stream carrier |
| `stdio` | `crates/busbar-transport-stdio` | yes — line-framed byte pump |
| `http` | `crates/busbar-transport-http` | yes — HTTP/1.1 + HTTP/2 (h2c and TLS+ALPN via `hyper::client::conn` h1/h2), SSE module, gRPC module folded in |
| `ws` | `crates/busbar-transport-ws` | yes — `tokio-tungstenite`-based sans-IO framer, RFC 6455 close codes, TLS via `tokio-rustls` |
| `grpc` | *(folded into `busbar-transport-http`)* | **in flight** — owner ruled 2026-09-29 to spin out a dedicated `busbar-transport-grpc` door layered on HTTP/2, "like ws on h1"; explicitly scoped as low-cost |

**New transport kinds needed beyond tcp/stdio/http/ws/grpc, flagged separately with cost:**

- **WebRTC (ICE/DTLS-SRTP media plane)** — needed for full OpenAI Realtime WebRTC and any future
  browser-native voice; busbar only has the signaling/minting side today. Cost: **L** — requires
  adopting/wrapping a WebRTC media stack (e.g. `webrtc-rs`), separate from the existing plain
  http/ws doors since media flows over negotiated SRTP, not the signaling channel.
- **SIP + RTP termination** — needed only if busbar originates/terminates SIP itself (e.g. for
  OpenAI's native SIP trunking) rather than fronting with Twilio (which busbar already reaches over
  plain `ws` via Media Streams). Cost: **L**. `docs/design/BUSBAR-1.6.0.md` #45 currently reads
  "raw SIP is not carried," but this matrix treats that as a flagged, standing owner/ARCHITECT
  decision point rather than a settled technical conclusion — it is called out here for a decision,
  not assumed either way.
- **QUIC/HTTP3** — not required by any spec in this matrix (A2A, MCP, all LLM dialects, and all
  voice protocols researched use HTTP/1.1, HTTP/2, WebSocket, or SIP/RTP only). No cost incurred;
  no gap.

---

### Sources

- A2A: https://a2a-protocol.org/v1.0.0/specification/ ; https://github.com/a2aproject/A2A/releases
- MCP: https://modelcontextprotocol.io/specification/2026-07-28 ;
  https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http ;
  https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization ;
  https://modelcontextprotocol.io/specification/2024-11-05/basic/transports (deprecated HTTP+SSE) ;
  https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning
- OpenAI: https://developers.openai.com/api/docs/api-reference/chat/create ;
  .../api-reference/responses/create ; .../guides/realtime ; .../guides/realtime-websocket ;
  .../guides/realtime-webrtc ; .../guides/realtime-sip
- Anthropic: https://platform.claude.com/docs/en/api/versioning ;
  https://platform.claude.com/docs/en/build-with-claude/streaming
- Gemini: https://ai.google.dev/api/generate-content ; https://ai.google.dev/api/live ;
  https://ai.google.dev/gemini-api/docs/live-api/get-started-websocket
- Bedrock: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html ;
  .../API_runtime_InvokeModelWithResponseStream.html ; .../API_runtime_ConverseStream.html
- Twilio: https://www.twilio.com/docs/voice/media-streams/websocket-messages ;
  https://www.twilio.com/docs/voice/twiml/stream ; https://www.twilio.com/docs/sip-trunking
- Repo: `origin/predev` (`c6556ddd2`) — `crates/busbar-transport-{http,ws,stdio,tcp}`,
  `crates/busbar-a2a`, `crates/busbar-plane-a2a`, `crates/busbar-llm`, `crates/busbar-plane-llm`,
  `crates/busbar-mcp`, `crates/busbar-plane-mcp`, `crates/busbar-plane-streaming`,
  `crates/busbar-voice`, `docs/design/BUSBAR-1.6.0.md`, `docs/design/1.6.0-QUESTIONS.md`,
  `docs/design/1.6.0-TODO.md`, `Appendix B`
