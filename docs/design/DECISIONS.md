# Busbar 1.6.0 — LOCKED DECISIONS (authoritative, append-only)

Rule: a decision here is LAW. If it has an enforcing gate, drift turns the gate RED — it cannot be
re-opened in conversation. If "Gate" says TODO, adding that gate is itself a task. Never re-litigate a
row here; cite it. Only VISION-1.6.0.md and 1.6.0-plane-extraction-LOCKED.md outrank this file.

| # | Decision (LAW) | Enforcing gate |
|---|----------------|----------------|
| 1 | **Architecture = core + plugins.** Core is a thin engine running ONE uniform per-unit governance workflow (Authenticate·Verify·Approve·Admit·Route·Meter·Audit) that every plane's data passes through. Core names ZERO plane types. | plane-purity (reverse), plane-abi-neutrality grep, teller-steps |
| 2 | **A PLUGIN IS A PLUGIN — exactly TWO requirements, every kind (plane included):** (1) compiled-in OR dropped-in (same contract, one loading path); (2) communicates ONLY over the ABI. No third requirement. | kind-isolation, construction:ports-only-tests, token-auth cdylib proof |
| 3 | **Plugin kinds:** store, secret, auth, hook, export, PLANE. That is the whole list. | kind-isolation:registry |
| 4 | **A DIALECT is a thing INSIDE a plane** (llm 6, mcp 1, a2a 1, streaming N). NOT a plugin, NOT a kind. No per-dialect crates, no Dialect trait/kind. **D36 CANCELLED.** | kind-isolation:truths (dialect kind ⇒ RED) |
| 5 | **admin & oauth2 are NOT plugins.** Compiled-in cleanliness crates, one-way dep on core, off the hot path. NO "control" plugin kind. **D37 CANCELLED.** | kind-isolation:registry/truths |
| 6 | **One crate per plane** `busbar-plane-<x>`; codec/dialect logic = modules inside it. Pure/IO split is plane-vs-transport, not a 3rd crate. | construction loc/surface ceilings |
| 7 | **A plane opens NO socket.** It declares transport needs as data at registration and asks core for a transport; ALL socket/DNS/pool/TLS/retry/breaker I/O lives in shared transport crate(s). Hot read/write = POD-by-pointer, zero-alloc, zero per-token host crossings. | source-denylist (hyper/reqwest/tokio-net out of plane closure) — TODO arm; perf/alloc gate |
| 8 | **Broker law:** plugins never talk to each other. Each declares needs+capabilities; core brokers by capability key (registry lookup, core names no concrete plugin). Coupling only ever points down (at core/contract). | plane-abi-neutrality, kind-isolation:deps |
| 9 | **Byte-identity = USER-OBSERVABLE contract, not internal-structure.** A 1.5.5 user upgrades to 1.6.0 and notices nothing. Internals may be rewritten freely; the oracle proves no user-visible byte moved. | shadow-oracle diff vs golden/1.5.5 (NEVER waived) |
| 10 | **The oracle's sole job:** prove no user-visible byte changed. A RED cell is a QUESTION, not a failure → owner approves (register w/ reason) or denies (fix to identical). Money-path bytes are sacred; default is deny-and-fix. | shadow-oracle; accept-register requires owner sign-off |
| 11 | **1.6.0 ships TWO distributions, one contract:** DEFAULT = everything compiled in (the 1.5.5 model, already green) — THE CUT SHIPS THIS. BARE-BONES = core + drop-in plugins. Plane folder-drop loader is a conformance follow-through, NOT a cut blocker. | build gate (both distributions) — TODO arm bare-bones |
| 12 | **1.6.0 = 1.5.5 + MCP + A2A + streaming + live voice.** New planes are additive, config-reached (add agents/tools/streams to config); they never touch the existing 1.5.5 experience. The internal re-architecture IS 1.6.0 (else it's just 1.5.5). | conformance (mcp/a2a/voice rigs) + oracle (1.5.5 unchanged) |
| 13 | **Marketing = vision; docs = truth.** A vision↔truth delta is a decision (agree/disagree → new row here), not an auto-fix. Owner updates marketing to fact-based AFTER code lands. | (process) |
| 14 | **Authoritative docs = VISION-1.6.0.md + 1.6.0-plane-extraction-LOCKED.md + this file.** Every other design doc is reconciled to them or deleted. No stale line may survive for an agent to resurrect. | doc-reconciliation pass |
| 15 | **Banned words:** defer / 1.6.x / later / "out of scope for 1.6.0". 1.6.0-or-bust. Feature-need changes come to owner with a real case; agent-laziness = fix the root. | (process) |
| 16 | **Worst-case ship date: Wed 2026-10-08 17:00 PDT.** Moves only on a named MAJOR EVENT (Commit-C non-decomposable + divergence cascade; systemic HIGH reopening money path; fleet outage). | 1.6.0-PLAN.md status |

| 17 | **One feature per plane, no `root-*`.** The per-plane compile knob is exactly `plane-<x>` (pull the plane crate + enable core's plane edge). The `root-*` family is transitional/vestigial: `root-mcp`/`root-a2a` are EMPTY, `root-voice` is a bare alias of `plane-voice`, `root-admin` only drags `tower`, and `root-llm` = `proto-llm` + `busbar-llm?/teller-waist` (the unit-plane path selector). END STATE default = `["auth-admin-tokens","hooks-ranking","plane-llm","plane-mcp","plane-a2a","plane-voice"]`. Collapse = rename `proto-llm`→`plane-llm`, make `teller-waist` unconditional (AFTER the legacy loop is deleted), delete all `root-*`, fold `root-admin`'s tower dep where used. Executes in the switch-over cutover cleanup — NOT a standalone edit (dropping `root-llm` before teller-waist is unconditional unwires the llm unit-plane path). | build (both distributions) green + owner's target default line |

Author: Matthew <dev3@getbusbar.com>. No AI attribution, ever.
