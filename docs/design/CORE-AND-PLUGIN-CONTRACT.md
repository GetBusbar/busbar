# busbar — Core & Plugin Contract (v0.1 — SUPERSEDED)

> **SUPERSEDED.** This draft describes a seam that plugins *call into* (`EngineHost`, "call the core
> metering seam"). That direction is exactly what the architecture abolishes: planes return facts,
> units decide, the kernel sequences. The authoritative contract is `ARCHITECTURE.md` (the only file
> builders read); the history is `ARCHITECTURE-AUDIT-LOG.md`. Do not hand this file to a builder.
> Its one lasting contribution — "an audit built on the definition must catch the voice-billing hole,
> or the definition is wrong" — lives on as the meta-tests in `ARCHITECTURE.md` §8.2.

> Purpose: the single, plain definition of what **core** is and does, and what **every
> plugin type** is and does — written so that an audit built directly on it **must** catch
> the voice-billing hole. If the audit misses it, this document is wrong, not the audit.
>
> Rule of reading: Part 1 (core) names **no plane, no dialect, no vendor, no protocol**.
> If you can point at a plane name in Part 1, Part 1 is wrong.

---

## Part 1 — CORE (the hub)

### 1.1 What core IS
- The **plane-neutral engine**. It runs one governed lifecycle for every unit of work.
- It operates only on **opaque, parameterized** units. It does not know what *kind* of work
  a unit is; it knows the unit crosses a boundary and must be governed identically.
- It is the **only** place the governed lifecycle exists. There is exactly one of each step.

### 1.2 Core's JOB — the ONE path every governed action takes (same path, every plane)

CANONICAL — the ONE path (7 verbs). The site today names 6; the missing verb is **Meter**
(see reconciliation note). Authoritative vocabulary:

> **Authenticate → Verify → Approve → Admit → Route → Meter → Audit.**
> A model call, a tool call, and an agent delegation are one operation on one path. The core
> routes the data and stays blind to the plane. One path, applied uniformly.

1. **Authenticate** — the caller is authenticated: presenting credential → principal / virtual
   key. Audience-checked. Fail-closed if unresolvable.
2. **Verify** — the destination is verified against what the operator approved (allow-list /
   trust pinning). **Verified strictly BEFORE any charge or work.**
3. **Approve** — the action is approved under its **grant** (authorization / scope).
4. **Admit** — the action is admitted against its **budget**: headroom is checked (fail-closed
   before charge); an optional reserve is taken here. This is the budget **gate**, not the debit.
5. **Route** — routed to a permitted destination: pool selection, breaker, failover,
   upstream-credential leasing, net-guard. The governed hop that performs the actual work.
6. **Meter** — the **spend is recorded/debited to the principal's ledger** once real cost is
   known. **One ledger, one accrual path.** *(This is the step voice skips.)*
   - One-shot action: settle actual cost after Route (as LLM does post-delivery).
   - Streaming/long-lived action: meter **continuously** and **hard-close mid-stream** the
     instant the budget is dry. This continuous form is a **CORE capability** offered through
     the seam — **never** plane-private.
7. **Audit** — audited into a durable, verifiable record (hash chain) the operator can read
   back, attributed to the principal. Neutral observability (metrics/labels/traces) and final
   settlement/refund/release ride here as mechanical sub-parts — not separate user-facing verbs.

> Reconciliation note (marketing ↔ code): the site names **6** verbs (Authenticate, Verify,
> Approve, Admit, Route, Audit). The **7th — Meter** — is the actual debit/record of spend
> AFTER Route, distinct from Admit's pre-charge budget CHECK. The site is **not wrong, but
> incomplete**: add "Meter" to the marquee path. That same step is exactly what voice
> under-implements. Site under-names it; voice under-implements it — one step, one gap.

### 1.3 Core NEVER
- Names a plane, dialect, protocol, or vendor — in code, in a label, or in a branch.
- Contains an `if plane == X` / dialect switch.
- Lets a unit **skip** a step or **supply its own version** of a step.
- Exposes a way for an external participant to do a step *except* through the seam (§3).

### 1.4 The seam
- Core exposes its lifecycle to external participants through **one neutral ABI seam**
  (today: `EngineHost` + the neutral crates `busbar-substrate` / `busbar-api`).
- Every core concern (identity, admission, **billing**, egress, observability, audit) is a
  **method on that seam**. A participant *calls the step*; it does not *reimplement* it.

---

## Part 2 — PLUGINS (general contract)

### 2.1 What a plugin IS
- An external participant that plugs into core **through the ABI and nothing else**.
- It supplies **kind-specific vocabulary/behavior** (a wire protocol, a storage backend, a
  hook, an identity source) — never a second copy of a core step.

### 2.2 Every plugin MUST
- Depend **only** on the ABI crates. Naming any other busbar library is a **contract
  violation** (and must be a compile error — see §4).
- Route every core concern through the seam. For billing specifically: **call the core
  metering seam, or do not meter at all.** There is no third option and no private ledger.
- Traverse (for planes) the full lifecycle **in core's order**, via the seam.

### 2.3 Every plugin MUST NOT
- Reimplement, shadow, or privately re-host a core step (its own budget cell, its own
  ledger, its own identity resolver, its own audit chain).
- Reach "backwards" into core internals (`busbar_core::…`).
- Ship a step that is "wired by comment" — documented as connected but unreachable in the
  shipped binary.

---

## Part 3 — PLUGIN TYPES (job · what it does · dependency rule · how it does billing)

> DOCTRINE (from the vetted site `docs/architecture.md`, authoritative for intent):
> *"One admission decision … the same budget and the same rate limits in the same step. **There is
> no separate MCP meter and no separate MCP budget.**"* and *"the token counts land on the ledger
> when the response stream completes; spend itself is never stored — it is derived at read time."*
> ⇒ A plane has **no meter and no budget of its own.** It lands usage on the ONE ledger through the
> seam and admits against the ONE budget. Voice's private `MeteringPort`/lease/`cap_nanos` is the
> violation — the fix is to remove the separate meter, not to wire a second one.

### 3.1 Plane plugins  (protocol planes)
- **Job:** own one protocol's wire vocabulary (its dialects), both inbound and outbound.
- **What it does:** translate the protocol ↔ the neutral IR; nothing else it does is its own.
- **Dependency rule:** ABI only.
- **Billing:** attribute each unit of work through the **core metering seam**
  (`meter_ledger` / `meter_series`), keyed to the presenting principal. A long-lived/streaming
  plane may need *continuous* metering with mid-stream cutoff — that is a **core capability**
  offered through the seam, **not** a plane-private lease.
- **Identity / admission / audit / observability:** all through the seam, in core's order.

### 3.2 Store plugins  (sqlite / postgres / mysql / valkey)
- **Job:** durable persistence of core-owned records (keys, ledgers, audit chains).
- **What it does:** implement the neutral **Store** trait; translate to a backend.
- **Dependency rule:** ABI Store contract only.
- **Billing:** N/A directly — but it is the **backing that makes core's billing/audit
  observable**. A store that silently drops a write is a hole of the same class.

### 3.3 Hook plugins  (webrequest, headroom, …)
- **Job:** observe / gate / transform at defined hook points.
- **What it does:** run at core-invoked hook stages via the hook ABI.
- **Dependency rule:** ABI hook contract only.
- **Billing:** may *inform* admission (e.g. headroom) but never *replaces* the metering step.

### 3.4 Auth plugins  (github / ldap / oidc; vault secret provider)
- **Job:** resolve identity / secrets feeding core's **Identity** step.
- **What it does:** answer the auth-chain ABI; return a principal or a secret.
- **Dependency rule:** ABI auth contract only.
- **Billing:** N/A — but a parallel identity path (a plugin that "admits" on its own) is the
  same class of hole as private billing.

---

## Part 4 — ENFORCEMENT (make the wrong thing impossible to compile)

- **Manifest gate:** a plugin crate's `Cargo.toml` may declare a busbar dependency ONLY on
  the ABI crates (`busbar-substrate`, `busbar-api`). Any other busbar path-dep → **build fails**.
- **Symbol gate:** a plugin's source may name `busbar_core::…` nowhere (already partially
  covered by plane-purity's BACKWARDS check; must become a hard, all-plugin gate).
- **Consequence:** the only billing symbols a plane can reach are the seam's. It can bill
  **correctly** (call the seam) or **not at all** (call nothing) — it **cannot** build a
  private/parallel billing path. This removes the exact failure mode voice hit.
- **Known current violation (this gate would fail today, correctly):** `busbar-llm` hard-deps
  `busbar-core` with ~920 production references. The gate flags it; the fix is repointing to
  the ABI re-exports. (Do not silence the gate — fix the dep.)

---

## Part 5 — CI (catch "not at all" from the USER's perspective)

Run **every plane** through the **same black-box battery against the shipped binary**, and
assert the **observable core effect** — not an isolated apparatus, not a mock:

| Battery test (per plane) | Asserts (observable, in core) |
|---|---|
| Send a real, authorized request | The **ledger shows non-zero spend** for the presenting key |
| Send with an over-budget key | The request is **blocked at admission** (before work) |
| Send with a wrong-audience / unauthorized key | **Blocked at identity** |
| Complete a request | An **audit-chain record** appears, attributed to the key |
| Complete a request | The **neutral metric** increments, attributed |

- **"proven" is redefined:** a capability cell is `proven` only if its test drives the
  **composition root / shipped mount**, never a hand-built apparatus + mock.
- Any plane that fails to produce the core-observable effect **fails CI** — this catches
  "not at all" by construction.

---

## Part 6 — THE RED TEST (does this definition catch voice-billing?)

Voice today: production binds a **plane-private** `LocalMeteringPort` (prices $0), opens
**uncapped**, and **never calls the core metering seam** — so no ledger row, no attribution.

- **Part 3.1 (plane billing rule):** voice reimplements billing via a private port instead of
  the seam → **contract violation.** ✅ caught by definition.
- **Part 4 (enforcement):** voice's private metering path is only possible because it can host
  its own billing symbols; the ABI-only + seam-only gates remove that option. ✅ prevented.
- **Part 5 (CI):** "voice session → ledger shows spend" **FAILS** (production prices $0, no
  attribution). ✅ caught by CI, without anyone naming voice in advance.

**Conclusion:** an audit built on this definition flags voice-billing three independent ways.
If a future audit does NOT catch a voice-billing-shaped hole, **this document is too weak** —
sharpen Part 1/Part 3 until it does.

---

### Open questions for review (red-pen these)
1. Is the 7-step core lifecycle (§1.2) right and complete, or is a step missing/misnamed?
2. Is "continuous metering with mid-stream cutoff" a **core capability** (my claim, §3.1), or
   something else?
3. Plugin types (§3): is the set complete (planes / stores / hooks / auth)? Any missing kind?
4. Enforcement scope (§4): ABI = `busbar-substrate` + `busbar-api` only — correct boundary?
