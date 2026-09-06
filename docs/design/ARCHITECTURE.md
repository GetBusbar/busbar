# busbar — Architecture v1.31 (parity revision 9 — §§1.2–1.4, 3.3, 3.6, 3.7, 4.2, 4.7, 6 amended to state the 2026-09-05 contract-gap decisions as rules)

> **busbar is a byte-governance router.** Bytes come in over a transport; a plane says what they mean;
> the kernel runs the same seven steps on every unit of work — Authenticate, Verify, Approve, Admit,
> Route, Meter, Audit — and bytes go out. The kernel does not know what any protocol is. Every plane is
> one crate and zero kernel lines. We position the product as an AI governance layer; the architecture
> is a protocol governance layer, and that is the growth the core allows.
>
> **Standard.** This is an accounting ledger. Instead of cash it moves company data. Think bank teller:
> can this principal do these seven things, in order? If so, do it — and post it. Every rule below is
> judged by "would this pass a bank's audit for money?" Where evidence is missing or contradictory the
> ledger posts the **lower** amount, flags it, and reports it for a verdict within `dispute_max_age` —
> never silently in the house's favour. Nothing in 1.6.0 is deferred.
>
> **Parity clause (governs every section).** From a user's perspective 1.6.0 is 1.5.5 — config,
> wire bytes, refusals, statuses, billing figures, the admin API, metrics, operations — with exactly
> three additions: the `mcp`, `a2a` and `voice` planes. The behavioural inventory
> `1.5.5-BEHAVIOUR.md` (≈ 2,900 cited rows extracted from the tag) is the contract that "identical"
> is measured against, and the oracle proves every row against the published 1.5.5 binary. The
> internal model in §2–§4 (one journal, holds, chains, dual control, units, planes) is free to be
> right; it may never change what a 1.5.5 user observes. Concretely: **the admission decision
> function is 1.5.5's** (charge `requests` at admit, budget compared as truncated cents including the
> fee lookahead, tokens post-hoc, the concurrent gauge) — the ledger's holds and slices are
> ACCOUNTING under that decision, never a second gate; a unit 1.5.5 admits, 1.6.0 admits, and the
> ledger records any resulting overdraft internally. Where this document below describes a stricter
> rule, it is an internal ledger rule; the user-facing outcome is the inventory's. §10 lists the
> reversions this clause forced and the single additive difference left for the owner.
>
> **Precedence.** This document is the contract until the contract crates exist; after that the crates
> win and this document is updated to match. It is frozen when §9.1's milestone M4 is green. It is
> **self-contained**; every number is **pinned** (§4.7's defaults table, §3.1's constants) or **measured
> at M2/M3** with its formula stated. Two documents govern arithmetic it inherits from 1.5.5:
> `docs/design/billing-unified.md` (the 1.5.5 pricing law — clauses 1–5 of §4.5 are derived from it;
> where it and this document disagree on the *storage layout*, this document wins) and 1.5.5's
> `cost.rs` (the verifier re-derives against both). Sections 1–4 and 10 name no plane and no dialect
> under the §1.3 scan definition; §8.3 runs the scan over this file. Undefined stream names are
> defined in §9.2.

---

## 1. The shape

### 1.1 Three blind axes, one small kernel

**TRANSPORT** (how bytes move) × **PLANE** (what bytes mean) × **UNITS** (what the kernel does about
them). Each axis is blind to the other two; only the kernel composes them.

- A **transport** cannot name a plane or a unit. It yields and writes frames, inbound (`listen`/
  `accept`) and outbound (`dial`); it knows no protocol, no principal. Transports are **in-tree only,
  never dynamically loaded**, inside the trusted computing base; the controls are review, the source
  denylist and the frame-honesty meta-tests (inflating and deflating).
- A **plane** names a transport only as a claim and never holds a connection; it names no unit and no
  other plane (a `NestedPlane` destination carries a key the plane's **claim config** declares, exactly
  as lanes are); it returns **facts and locators** — never an amount, a decision, a credential, a price, a
  scheme outside its claim; it may name a **lane** only from the config-declared set for its claimed
  upstream (the trust unit re-derives it against the allow-list, which bounds the damage; the lane
  cross-check detects inconsistency between the plane's two legs and the kernel-sealed destination lane, and a uniformly lying plane is
  what the expensive-lane meta-test and the variance rule's kernel-derived lines are for). It is pure over its inputs and performs no I/O; its durable state is
  kernel-held records reached only through Route legs (§2.3 `PlaneRecord`).
- A **unit** takes facts + a principal + the kernel's clock and nothing else; it names no plane and no
  transport; it never calls another unit.
- The **kernel** is the **registry** and the **Teller** plus what the loop needs: frame pump, sessions
  and scheduler, in-flight table, Ticks, recovery, slices/leases/fencing, drain, the closed grammars.
  The WAL, group commit and chains live in `busbar-unit-wal`; the kernel verbs live in
  `busbar-unit-verbs`. **LOC ceilings, gated as one union and per file, by call-graph** (a
  `busbar-unit-*` file reachable from the Teller loop **without crossing a sealed unit-trait boundary**
  — helpers the loop calls directly, not the units behind their traits — counts against the kernel
  ceiling): `busbar-kernel`
  ≤ 8k — Teller loop 1.5k · pump/scheduler 1.5k · in-flight/sessions 1k · recovery 0.8k · slice/lease
  0.8k · registry + generations 0.8k · grammars incl. JSON span scanner 0.8k · Ticks/drain/fleet 0.5k ·
  arena/masking 0.3k; `busbar-caps` + `busbar-contract` ≤ 3.5k **of plugin-visible SURFACE** —
  non-blank, non-comment code lines under each crate's `src/`, excluding `#[cfg(test)]` modules and
  `src/tests/`; the proofs (overlap totality over the selector-form pairs, the lint symbol lists, the
  compile-fail fixtures and their positive companions, the honesty tables) are not surface and live
  in each crate's `tests/` or `fixtures/`. Measured and gated by `scripts/loc-surface.py`
  (`--ceiling busbar-contract,busbar-caps=3500`), which the construction gate runs as
  `surface-ceiling:contract+caps`. Two crates carry their own surface ceilings beside it, because
  each is contract surface that a plugin author does not read and a ceiling nothing measures is a
  ceiling that has been abolished rather than met: `busbar-grammar` — the closed JSON span grammar,
  std-only, named by the kernel and re-exported as `busbar_contract::spans` — ≤ **0.5k**, gated as
  `surface-ceiling:grammar`; `busbar-contract-transport` — the transport-facing contract: the
  connection and listener handles, the detached stream, the closed transport failure and close
  codes, the arrival record, the upstream address, the reserved transport fact keys, the kind's ABI
  generation and the composition check — ≤ **1k**, gated as `surface-ceiling:contract-transport`.
  All `busbar-unit-*` ≤ 45k (incl. verbs
  ≤ 15k); union ≤ 56k. 100 % (non-equivalent) mutation floor: Teller loop, WAL/group-commit, recovery,
  slice/lease, cost, usage, ledger.

### 1.2 Core → plugin. Never plugin → core.

Every plugin is passive: the kernel registers it, calls it, consumes what it returns.
- **Manifest allow-list**: `busbar-contract`, the closed grammar it is written on and re-exports
  (`busbar-grammar`), plus reviewed third-party crates; any dependency on `busbar-kernel`,
  `busbar-caps`, `busbar-contract-transport`, a `busbar-unit-*`, another plane or a transport is a
  CI failure.
- **Source denylist** (transitive via `cargo metadata`), scoped to the **pure kinds**: plane, hook,
  static auth schemes that are pure, egress-auth-scheme, and the FFI transform crate: any path under
  `std::{net, fs, process, os, env}`, `tokio::{net, fs, process}`, `async_std::*`, `libc`, `reqwest`,
  `hyper`; allow-list empty at hour 0. Meta-test: a socket-opening plane is red. **I/O kinds** — store,
  secret, export, and network-backed auth plugins (LDAP, OIDC/JWKS) — own their I/O by definition; they
  are bounded by the signature, the `Load` entry, a kernel-enforced per-call deadline, an `Access` entry
  per external call, and review.
- **Purity** (pure kinds): an AST scan rejects interior mutability in the plugin crate's own struct
  fields and statics; dependency purity is review-only (§3.7 says so); the determinism meta-test proves
  a stateful plane is red. Cross-frame codec state lives only in `PlaneSessionState` (§3.1).
- Plane, hook, pure-auth, egress-auth-scheme and secret crates are `#![forbid(unsafe_code)]`;
  transport, ABI, loader, store and export crates are `deny` with a reviewed allow-list; the one FFI
  transform crate is a dependency of the plane that uses it and carries its own `deny` entry.
- `Ctx` carries exactly one **resource** handle — the per-unit arena; `clock` and a per-unit **entropy**
  value are read-only kernel value sources; the rest are borrowed views. A plane reads no random source
  of its own: where a codec must mint a value with native shape and entropy (an echoed request id in an
  error envelope, matching a provider's own wire form), the entropy is supplied through `Ctx`, never
  drawn by the plane itself, so the purity and determinism rules below hold without exception. The ABI exposes no `mount`/`serve`/`bind`/`on_upgrade`; the one carve-out is the 1.5.5 confined plugin-route surface (`/hooks/{owner}/*`, `/exports/{owner}/*`, `/metrics`), which the KERNEL mounts on the plugin's behalf from its declared route table, verbatim (PB-31).
  The contract is feature-invariant (gate scan). One base `Plugin` trait, one registry type; unit
  traits are sealed.
- **Mandatory in-tree plugins**: `auth-lease` (peer frames, node leases) and `secret-local`
  (file-backed keyset under `data_dir`, mode 0600; it signs checkpoints, seals the replay cache, holds
  pseudonym sub-keys and transport keys when no other secret plugin is configured — so a zero-config
  1.5.5 boot has every key it needs). **Keyset continuity**: every public half is sealed in `Policy`
  and each `Checkpoint` (so `verify` checks signatures against the journal, never the disk); the keyset
  has ONE deployment keyset: `secret-local` MINTS a keyset only under a `Bootstrap` unit (the first boot of a deployment whose store holds no `Bootstrap`); `Bootstrap` seals its fingerprint; a node that boots against a store holding a `Bootstrap` with a fingerprint it does not have refuses `KeysetMissing { remedy: busbar keyset import }` — and `busbar keyset import <sealed-file> --recipient-key <file>` is an OFF-NODE CLI (the recipient keypair is the operator keypair from `busbar operator keygen`, or one from `busbar keyset recipient-keygen`; `KeysetImported` records the recipient fingerprint) (like `operator keygen`) acting on a STOPPED node's `data_dir`, outside the verb posture, replacing any never-leased locally minted keyset, journaled as a `Bootstrap`-class `KeysetImported` entry on the node's next boot; `auth-lease` refuses a lease to a node whose fingerprint differs (§10 names the ceremony; §4.8's migration sequence; battery cell: a 3-node upgrade where B and C refuse `KeysetMissing`, are imported offline, then all three serve). There is no on-node `import_keyset` verb — one principal, one pseudonym, fleet-wide; the keyset is exported sealed to the operator/escrow set by `export_keyset` (irreducible verb) and restored by
  `busbar keyset import` (off-node); rotation is a `Policy` entry signed by the retiring key; a boot that finds a journal
  but no keyset refuses with `KeysetMissing` (remedies, all OFF-NODE on a stopped node: `busbar keyset import`, or `busbar chain-break` / `busbar store-restore` / `busbar reseal-epoch-floor` — the disaster-recovery operations are off-node CLI operating on `data_dir`, journaled on the next boot, outside the verb posture; battery cell: keyset lost, journal present).
- **Deadlines and stalls**: every call into an I/O kind or a store runs on a bounded blocking pool
  (`spawn_blocking`-class; the threading rule is stated in the contract crate; `scripts/blocking-ffi-lint`
  is in the gate) with a per-kind deadline → `Failed(step, PluginTimeout)` (a hook → `on_failure`). A
  pure plane call that neither returns nor panics is detected by the node Tick ("no step advance AND no frame relayed for
  `max_unit_duration` and not marked") → `Stalled`: alarm, drain, then process abort at a bound so
  recovery posts `recovered` — for `http`/`sse` units the sweep ALARMS only and never ends the unit (a long-silent 1.5.5 stream has no idle cut; PB-48).

*Trust boundary.* Structural for pure static plugins as above. **A dynamically loaded plugin is fully
trusted native code inside the process; the design provides no guarantee against it beyond the
signature** — 1.5.5's `plugins.trust` gate verbatim (PB-11), with the operator key set as an additive layer — `any` under `operator: unset` (journaled, alarmed, Appendix A), closed by `set_operator_key`; each load is a `Load` journal entry (kind, key,
digest, signer; for a store declaring `FLEET_SAFE`, the hash of the N-node conformance verdict). **The
binary is gated the same way**: `Policy` carries an operator-approved binary-digest set; a node whose
digest is not in the set refuses to serve.

### 1.3 Open vocabulary, closed shape

**The kernel has no closed enum a plugin could need to extend. Everything a plugin varies is a key into
a registry or config. Only structure is closed.**

Closed (structural): steps; `UnitEnd`; `Origin`; `Direction`; `Ingress`/`Progress`; destination kinds;
selector, location and handoff forms; the JSON span grammar; quantity sources; cap-dimension SHAPE (`NanoUnits | Requests | Concurrent | Class(MeterClassId)` — any declared meter class is cappable by key, so `tokens`, `tokens_in`, `tokens_out`, `bytes`, `messages` are instances, not variants); hook
seats; journal entry classes; capability types; kernel verbs (§4.7); the dual-controlled config key
list and its defaults; the peer envelope; the effects-spec outcome classes (§8.1).

Open (declared by the plugin, priced or bound by config, dispatched by key): claims; op classes; meter
classes; credential schemes; egress auth schemes; transports and their composition; session, transport,
content and hook facts; record schemas; plane admin verbs (read-only introspection); interrupt and
pacing facts; config schemas.

**Config-derived keys are leaked once.** An id, name or other open-vocabulary key that is only known at
config time (a lane, a dialect, a configured plugin key) is leaked into a `&'static str` exactly once,
by the composition root, at that plugin's registration — never per connection, per dial or per call. The
resulting allocation is fixed at registration and is counted in §10's `fixed` term of the peak-RSS
formula; a leak anywhere outside registration (one per dial, one per frame) is a defect, not a variant of
this rule.

**Lean-core scan** (mechanical): every string literal and `const &str` in kernel and unit crates is
compared against the union of all registered open-vocabulary keys and dialect names; any match fails;
`if kind == …` / `match` over an open vocabulary fails. **Doc scan** (mechanical): the deny list is the
<!-- doc-scan: exclude -->
union of §6's plane keys, §6's dialect names, and a pinned word list; the scan runs over §1–§4/§10 of
this file (the marked block `<!-- doc-scan: exclude -->` … `<!-- /doc-scan -->` that states the list and the allow-list is itself excluded); the pinned word list is: `chat`, `completion`, `prompt`, `assistant`, `agent`, `realtime`,
`speech`, `transcribe`, `audio`, `image`, `embedding`, `model`, `tool call`, `sampling`, `mail`,
`message queue`, `tunnel`, plus every upstream vendor name in §6 (multi-word dialect names are matched as PHRASES, never per token)'s dialect column; the scan matches on WORD BOUNDARIES and skips backticked 1.5.5 identifiers (`ModelCfg`, `model_unpriced`); the allow-list, each
with its reason: transport-grammar terms (header, query, path, port,
ALPN, SNI, TLS, DTLS, datagram, stream, keep-alive); the JSON span grammar; kernel-verb surface names
and `/usage`, `/audit`; "dialect" as the design term for a plane's wire vocabulary (never a specific one); "admin" anywhere as the kernel-verb
plane's name; "codec", "transform", "media", "emission clock", "pacing", "turn" — generic
names of plane-side byte transforms, the kernel's rate-shaped write path and the duplex unit boundary;
store and transport keys are out of
scope.
<!-- /doc-scan -->

### 1.4 Plugin kinds

| Kind | Closed shape (kernel calls) | Open vocabulary (plugin declares) |
|---|---|---|
| Plane | 7 codec, 7 fact, 2 introspection methods; `SessionPlane::open_session` / `open_upstream` — **18 call sites** | `KEY`, `CLAIMS`, `OP_CLASSES`, `METER_CLASSES` (each entry: key, `family`, `direction: Input | Response | CacheRead | CacheWrite | Kernel`, default divisor — the card may price but never re-family; "class family" everywhere means this field), `SESSION_FACTS`, `CONTENT_FACTS`, `RECORD_SCHEMAS`, `INTROSPECTION_VERBS`, `INTERRUPT_FACT`, `EGRESS_PACING_FACT`, `CONFIG_SCHEMA` |
| Transport (in-tree) | `arrival / listen / accept / dial / frames / write / upgrade / close / unit0_refusal` (async, boxed futures) | `KEY`, `SELECTOR_FORMS`, `EGRESS_SELECTOR_FORMS`, `COMPOSES_OVER`, `HANDOFF`, `SESSION`, `SESSION_BOUND`, `UNIT0_TRIGGER`, `UPGRADES_TO`, `HANDSHAKE_TRIGGER`, `TRANSPORT_FACTS`, `DECODES_PAYLOAD` |
| Auth (ingress) | `verify(credential, arrival, clock, prior: Option<ChallengeState>) → CredentialFacts | Challenge { bytes, state, rounds_left } | Pass` (`Pass` = abstain, 1.5.5's chain continuation; the migrated `auth.chain` runs through `run_chain_cached` semantics, the credential cache applying to EXTERNAL modules only — the `keys` arm is cache-exempt — PB-35) (the proof of round n arrives with the state of round n−1); `refresh(clock) → KeyMaterial` (Tick-driven) | `KEY`, `LOCATIONS` (arrival forms), issuer config, `IO: bool` |
| Egress-auth scheme | `decorate(cfg, &EgressBody, signer) → AuthDecoration`; `continue_handshake(state, &Frame, signer) → AuthDecoration` for multi-round schemes (the upstream challenge reaches round 2 here) | `KEY` |
| Store (kind `store`; native ABI **5**; every 1.5.5 dynamic plugin LOADS through an in-tree ADAPTER per kind at the exact 1.5.5 loader windows (store 2, auth 1–2, hook 1, export 2, secret 1), so a 1.5.5 plugins.yaml boots unchanged — parity clause, no `PluginAbiTooOld` for any 1.5.5 plugin) | `append_batch / replay_batch / reserve / release / heads / heartbeat / elect_checkpoint / claim_key / void_claims / replay_put / replay_get / session_put / session_remove / sessions_for / record_put / record_get / record_scan / legacy_cells_read / legacy_cells_write / legacy_audit_head / backup_watermark / purge_before` | `KEY`, `ABI_FLOOR`, `FLEET_SAFE`, schema versions, measured max sustained record rate |
| Secret | `resolve`, `watch`, `sign`, `seal/unseal` (SIV-AEAD, deterministic); `watch` is inert for every migrated 1.5.5 ref (resolved once at 1.5.5's site, PB-34) | `KEY`, `REF_GRAMMAR` |
| Hook | `observe(seat, &HookView) → HookFacts` at the four seats `Before(Approve)` (1.5.5 `Request`), `After(Admit)` (1.5.5 `Candidate` — AFTER the draw, so a restrict-to-empty veto consumes the `requests` slot exactly as 1.5.5's late reject did), `Before(Route)` (1.5.5 `Routing`, also after the draw), `After(Route)` (1.5.5 `Response`); `HookFacts { permutation: Option<Permutation> (None = abstain, 1.5.5's `Abstain`), restrict: Option<CandidateSet>, veto: Option<VetoCode>, rewrite: Option<IrPatch>, tap: Facts }`; COMPOSITION at a seat: hooks at a gate seat run CONCURRENTLY (`join_all`) against the same t0 candidate set, the reject winning by chain position — 1.5.5's order (proxy-hooks :126-130); sealed in `Policy`, `restrict` sets intersect, the first `veto` wins, the LAST non-`None` permutation wins, re-validated against the final restricted set (PB-5; a ranked order is walked as-is, as 1.5.5 does); the SWRR floor applies when every permutation above it is `None` OR when no ranked lane passes the pick-time gate (in this hop's set, non-zero weight, `ready_in` peek) — 1.5.5's fall-through, PB-5; `restrict` carries `on_empty ∈ { weighted | reject | first }` (the 1.5.5 key, default `reject` — PB-1; `weighted` = for a GATE, skip only that gate's restriction (candidate set unchanged), for the BASE POLICY, escape to the full pool under the SWRR floor (PB-28); `first` on the restrict-empty arm takes the SAME 503 as `reject` (1.5.5's `if matches!(on_empty, Weighted)` else-branch; `first` orders only as an `on_error`-chain terminal, PB-1)), sealed per migrated hook at `Migration`; a MIGRATED 1.5.5 `Request`-stage hook seats `After(Admit)` ahead of the `Candidate` hooks, in 1.5.5's order (PB-6, PB-46 — `Before(Approve)` is a 1.6.0-native seat); `After(Route)` is `Tap`-only (the response has relayed and the fee is decided) and fires once per request that reached the forward path with 1.5.5's `outcome`, OR once on a pre-forward auth refusal on a hooked pool with the synthetic `rejected_by_auth` (OWNER DECISION, PB-84 — every other pre-forward refusal still never taps), detached under `MAX_INFLIGHT_TAP_NOTIFICATIONS = 1024` (PB-84) — 1.5.5 `Gate` = veto/restrict/rewrite, 1.5.5 `Tap` = `tap` facts only; a `rewrite` is applied by the kernel to the `Ir` over the SPOOLED BODY (the head plus the spill, retained until the egress body is encoded at Route or the unit ends — the same bytes the pointers price; never to bytes on the wire; the patched body lives in the spill under `spill_budget`, so a 1.5.5 full-body rewrite gate works unchanged), price-neutral by default (`max_priced_delta = 0`), journaled `Access` with pre/post hash, bounded by `max_priced_delta`; the compiled-in 1.5.5 ranking strategies are in-tree hooks of this kind | `KEY`, kind (`Tap` | `Gate`), seats, `HOOK_FACTS`, `on_failure`, `max_priced_delta`, `may_change_destination`, `may_rewrite` |
| Export | `receive(JournalEntry | ContentFacts | Segment) → Ack`; `ANCHOR { write(head), read_head(n) }` | `KEY`, sink, format, retention it owns |
| Rate card (config) | unit price = f(lane, meter_class, extras), with a `*` default lane row (used by `SessionAccrual` on sessions that dialed nothing; absent while any bucket declares a `session_seconds` class → boot refusal `MissingDefaultLaneRow`) with a bucket-level tier multiplier (§4.5); versioned; quantity sources per (plane, transport); permitted lanes per op class; max unit price; lane aliases; `KernelVerb` section (default 0); **bucket chain and cap dimensions** (§4.6) | meter classes, prices, windows, frame selectors, divisors |

**The store trait is typed after the published ABI-2 store protocol**, extended with the 1.6.0-only
operations: the twelve ABI-2 methods (`heartbeat`, `elect_checkpoint`, `claim_key`, `void_claims`,
`replay_put`, `replay_get`, `replay_batch`, `legacy_cells_read`, `legacy_cells_write`,
`legacy_audit_head`, `backup_watermark`, `purge_before`) are the request/response shapes the shadow
oracle already proves against the released stores; `append_batch`, `reserve`, `release`, `heads`,
`session_put`, `session_remove`, `sessions_for`, `record_put`, `record_get` and `record_scan` are the ten
1.6.0-only additions. No store method signature is inferred from prose.

**`INTROSPECTION_VERBS` names one thing.** A plane's per-plane, read-only introspection list is
`INTROSPECTION_VERBS`; it never shares a name with the kernel's own closed `KernelVerb` table (§4.7),
which is the admin plane's surface, not a plane-declared one. The contract's closed `Refusal` reason
code maps onto the admin plane's rendered error codes through one ratified table, owned by the admin
plane: several reasons share one code (reasons are opaque to a client, §3.1), and that table — not a
per-implementer reading — is the admin plane's mapping of record.

Registration is the only way in. Zero of any kind is valid, except the mandatory in-tree `auth-lease`, the in-tree `memory` store (the default when a config names none — 1.5.5's default)
and `secret-local`.

---

## 2. The Teller

### 2.1 Unit, frame, session, stream

- A **frame** is transport bytes with a direction, a stream id and transport meta (`bytes`; and
  `transport_units` only where `DECODES_PAYLOAD`). It has no meaning.
- A **unit** is one governed transaction: one journal authorization (hold) and one settlement, whatever
  the frame count. The **plane delimits units** from frames. **Large bodies**: a transport yields a request body larger than the connection cursor as a HEAD frame (the scanned prefix, ≤ the cursor cap) followed by body-chunk frames; the plane returns `Open` for the head and relays the chunks through `encode_ingress_frame` under the unit's hold, the ingress estimate comes from the declared length (`Content-Length`-class transport meta), and with NO declared length (chunked) the body is spooled to its end under `spill_budget` BEFORE Admit and the input classes are sized exactly (1.5.5 buffered the whole body too; oracle cell: chunked ≥ 1 MiB body at a budget boundary) and EVERY declared pointer (lane locator, op class, idempotency) keeps resolving — and whenever a pre-Route hook declares the body key or `may_rewrite`, or an auth location is `Signed { over: Body | Both }`, the "deepest pointer" is END OF BODY, so gates, rewrites and body signatures always see the whole body (spooled under `spill_budget`; §10 names the RSS term) — across the body-chunk frames BEFORE `Open`: the span scanner runs incrementally, chunks are spooled into a per-connection spill buffer charged to a SEPARATE node-global `spill_budget` (§4.7: `max_inbound_concurrent × request_body_max_bytes`, exactly what 1.5.5 buffered, so no request 1.5.5 accepted is ever refused — PB-18) in actual bytes, and the unit opens when the deepest declared pointer has resolved or the declared length ends — no pointer is ever evaluated over a truncated prefix (oracle cell: ≥ 1 MiB body with the lane key serialised LAST, byte-identical; §10 names the spill in the RSS formula) — so a 1.5.5 request up to its `request_body_max_bytes` (default 32 MiB) is served unchanged with a 64 KiB cursor (a §10 row; oracle cell ≥ 1 MiB body, byte-identical).
- **One-shot transports** (`SESSION = false`): no Unit 0, no session, `Ctx.session = None`. **Session
  transports** (`SESSION = true`) open a session at Unit 0 — a kernel-owned pairing of a client
  connection with **zero or more** upstream connections, node-local, in the **node-global sharded session
  table**, registered in the store directory (`session_put`, batched with the segment; dropped by
  `session_remove` at close and by lease expiry). A session is **bound** — its principal cached until upgrade, revocation or a failed re-check — when the top transport declares `SESSION_BOUND = true` OR a Completed Unit 0 / Handshake unit returns `CredentialFacts { session_bindable: true }` (an authenticate-once protocol on an unbound transport binds this way; cell: AUTH then N messages on one connection); otherwise it is **unbound**: every unit re-authenticates and `FromSession` is refused
  (`Refused(Authenticate, SessionUnbound)`). **Outbound sessions** are sessions too.
- **Concurrency.** Per `(session, stream, direction)` at most one **open** unit; **one-shot units**
  (`OneShot`) never occupy the open slot and run under K (default 4).
- **Origins** (closed): `Client` · `Provider` · `Tick` · `Arrival` · `Handshake` · `Bootstrap` ·
  `Nested { parent }` · `Delivery { parent }`.
- **Steps** (closed): `Arrival, Decode, Authenticate, Verify, Approve, Admit, Route, Meter, Audit,
  Encode`; `Arrival`, `Decode`, `Encode` are kernel-owned with kernel-held tokens.
- **The in-flight table** (node-global, sharded) owns every live unit's `HoldCell` — a two-state slot
  `Arrival(h) → Admitted(h')` (one CAS transition consumes the arrival hold; either state is takeable
  exactly once) — plus the accrual counter, cancellation token and step state; the Teller borrows; the
  exit path and the Tick sweep `take()`.

### 2.2 The loop — every unit, every transport, every plane, no exceptions

```
0  ARRIVAL       kernel gate: size, rate, source, cursor and spill budgets (`in_flight_cap` is enforced on INSERTION INTO THE IN-FLIGHT TABLE for every origin — client, provider, nested, delivery, tick — `Refused(Arrival, InFlightCap)` for client units, `Refused(Decode, InFlightCap)` for the rest — with `in_flight_reserve` (10 % of `in_flight_cap` when any claimed transport declares `SESSION = true`, else 0 — parity-neutral for a one-shot-only 1.5.5 config; named in §10) and units arriving on the ADMIN listener are EXEMPT from `in_flight_cap` (1.5.5 capped the data listener only — every data-listener route incl. `/stats`, `/v1/models`, `/metrics`, `/auth/token`, `/healthz` is under the cap, PB-7; cell: saturated `in_flight_cap` → the admin listener still answers) held back for provider frames of ALREADY-OPEN sessions, so shedding lands on new Unit 0s before paying duplex sessions — a capacity reason class OUTSIDE the session hard-close list: a CLIENT frame is counted into the Aggregate and the session stays open; a PROVIDER-origin unit refused at the cap OR at any later step (Verify/Approve: floor line, session continues; Admit for a money reason — OverBudget, GroupFrozen, Unpriced, OverdraftCeiling, StaleSlice, DurabilityUnavailable — floor line AND hard-close, so a dry bucket sees at most one push) — content the upstream will invoice — posts a kernel-floor `estimated` line into the session's open unit — or, when the session has NO open unit (an unsolicited push between turns), as a standalone `Transaction` entry whose subject is the session's principal (Unit 0's, or the last unit's on an unbound session), backed by a synchronous slice draw under the `late_accrual` overdraft rule — lands on the exceptions report and hard-closes the session (never dropped unposted; cell: provider push at the cap, session idle); the heartbeat/sweep Tick NEVER occupies a slot (zero hold), so it always runs; a `SessionAccrual` Tick unit DOES enter the table under `in_flight_cap` and, if refused there, the NEXT accrual unit is sized at elapsed-since-last-settled-tick × price (capped at `session_idle_max` × price — a catch-up that would exceed it posts the cap flagged `estimated`, journals the excess seconds, and closes the session; `late_accrual` when it spans more than one tick) so priced session time is never dropped — so the table's size is the bound the crash-exposure formula uses) (from the ArrivalRecord). Credentials are
                 MASKED: the span each arrival-resolvable Location names is copied into a per-connection
                 credential slab (bounded by the cursor cap; oversize → Refused(Arrival, CredentialBudget) — distinct from CursorBudget: the slab, not the cursor)
                 and replaced in the FrameCursor by same-length fill. HandshakeFrames hand the auth plugin
                 the bounded raw prefix at step 0; its facts are consumed at step 1. The admission unit mints
                 an in-memory arrival hold into the HoldCell. Refusal = Refused(Arrival), subject = Arrival{..}; a PRE-DECODE refusal is rendered by the KERNEL through the transport's generic envelope (no plane is known yet — 1.5.5's non-dialect JSON 503 with `Retry-After`, byte-identical; cell: saturated `in_flight_cap`) — EXCEPT the body-size refusal, which 1.5.5 raises inside the handler AFTER auth and protocol detection and renders dialect-shaped (PB-60: `request_body_max_bytes` is checked after Authenticate, `KIND_REQUEST_TOO_LARGE`, the literal message, Bedrock `x-amzn-*` headers).
                 ANONYMOUS declines are group-committed and never gate the refusal bytes (a decline may be
                 lost within one commit window after a crash — accepted, declines move no money; measured).
                 Above rate R per source, or above a node-global decline rate, declines are COUNTED into one
                 per-window Aggregate entry (exact count, distinct sources, first/last, per-(transport, claim,
                 reason) counts) — a 10×R drive equals the aggregate.
decode           plane.decode_ingress → Ingress::{NeedMore | Open | OneShot | Handshake | Frame | Close | Discard { reason }},
                 or plane.decode_response → Progress::{NeedMore | Open | OneShot | Frame | Terminal | Discard}.
                 Discard drops the frame, counts it into the Aggregate, changes no state (on SESSION_BOUND =
                 false datagram transports a decode failure is Discard, never hard-close). Frame/Close/
                 Terminal carry `for_: Option<CorrelationRef>`; a second Open on an occupied direction is
                 Refused(Decode, OpenSlotBusy) — rendered, the session stays open; INTERRUPT_FACT is evaluated BEFORE the slot check so a superseding Open on an occupied direction reaches the CAS. The KERNEL constructs the Unit and is the sole writer of key,
                 origin, session, reply_to. A HANDSHAKE_TRIGGER frame opens an Origin::Handshake unit.
1  AUTHENTICATE  auth unit ← the CLAIM's scheme (plane.authenticate() may only narrow within the claim's
                 declared alternatives, else Refused(Authenticate, SchemeNotDeclared)) + kernel Credential →
                 principal, or (inside a Handshake unit — one the plane opened with `Ingress::Handshake` or the transport with its native trigger) Challenge { bytes } → the challenge is
                 delivered to the client as the Handshake unit's Route leg (Client { Deliver }), the proof
                 arrives as the next HandshakeFrames, ≤ challenge_max_rounds and challenge_max_bytes; `Principal::Anonymous` (the arrival subject; on every 1.5.5 surface it has NO bucket and renders `actor_id()` as the literal `"anonymous"` — audit rows, chain hashes and idempotency namespace unchanged; the `kernel:anonymous` attribution bucket is internal only; a synthesized principal whose id starts with `group:` or `vk_` is refused exactly as governance :77) until
                 facts arrive (§4.7). The secret an
                 auth scheme needs (stored verifier, static key) comes through the
                 secret plugin to the auth unit, never to a plane. Revocation gates NEW units only; an in-flight `http`/`sse` unit runs to its 1.5.5 end (PB-9); a unit on a 1.6.0 session plane ends `Aborted(Kernel { Revoked })` at the next Tick. Revocation set and policy epoch are
                 kernel-derived from the journal tail and re-checked on EVERY unit.
2  VERIFY        trust unit ← plane.verify() → Vec<VerifiedDestination> over the kinds permitted for this
                 origin (§3.6): allow-list; transport key from the registry; lane permitted for the DRAFT's op class (the hold is sized at the max over every op class the principal may use; a mislabelled op class is caught by `audit` → `MeterDisputed`);
                 unit price ≤ max (1.6.0-native cards only — a 1.5.5 rate card has no max-price field and the check is absent, never an exclusion); tripped, budget-exhausted and at-capacity lanes are EXCLUDED from the walk exactly as 1.5.5's try_admit excludes them (PB-3) — weight-0, dead / `BudgetExhausted` and breaker-open lanes are filtered BEFORE the SWRR credit walk (`select_weighted_for`), and only an at-capacity lane reaches `try_admit` inside `pick_among` after selection, so only an at-capacity lane consumes an SWRR turn (PB-57); an all-excluded pool still proceeds through Admit (the `requests` slot is drawn and retained, as 1.5.5 charged before its 503) and ends at the pool's `on_exhausted` terminal (PB-4) (cell: every lane hard-down → one slot consumed, `fee_count = 0`).
3  APPROVE       scope unit: required scope from (claim, op_class) in Policy; plane.approve() gives resource
                 locators only; hook facts (veto is a closed code; the first veto at any seat wins).
4  ADMIT         THE DECISION IS 1.5.5's (parity clause): the admission unit evaluates 1.5.5's CHECK-THEN-CHARGE
                 exactly (pass 1 checks every bucket and returns on the FIRST blocking bucket in pool-filtered chain order, charging nothing; pass 2 charges under the same shard guards — PB-22) — `requests` and `billable_requests` +1 on EVERY bucket of the pool-filtered chain, the uncapped key bucket included (PB-22), `budget` compared as
                 truncated cents of derived spend plus the fee lookahead against the cap, `tokens` compared
                 post-hoc (Σ settled ≥ cap blocks the NEXT unit), `concurrent` as an instantaneous gauge,
                 pool scope, `on_exhaust: downgrade` cascade, frozen groups, the one dialect whose quota status is 400 rather than 429 (inventory G2) — and the
                 refusal wire (status, `kind`, message, `Retry-After`) is the inventory's, byte for byte. The
                 HOLD below is accounting under that decision: it sizes the ledger's reservation, it never
                 refuses a unit 1.5.5 would admit (an under-sized hold simply tops up or posts `Overdraft`
                 internally). Hold-sizing rule — per meter class c: for the classes whose `METER_CLASSES.direction` is `Input`, `CacheRead` or `CacheWrite` (they PARTITION the same bytes; `Kernel`-direction classes are outside the partition and outside `max_response`) the WHOLE ingress-derived estimate is assigned to the single most expensive of them and 0 to the others — Meter settles to the reported split — so Σ_c here equals the max in `max_hold`; that class takes the
                 exact ingress-derived estimate_c; for a response-family class the max_response-derived
                 estimate_c (§4.7); nano-units hold, = ⌈(Σ_c estimate_c × the MAX
                 unit price_c over the verified set (price is `f(lane, meter_class, extras)`; op classes enter only through the lanes they permit) (the set Verify built for the DRAFT op class; lanes of other op classes are not held — a mislabelled op class is caught by `audit` → `MeterDisputed`),
                 plus the fee line (`per_request_fee` × 10^7 nano-units × 1, only for `Origin::Client` `Open`/`OneShot` units whose verified set contains an `Upstream`/`SessionUpstream` candidate — 1.5.5 counts the fee toward the
                 budget)) × the CHAIN's `tier_bp` ÷ 10^4⌉ (one tier per chain — `TierMismatch` otherwise; a 1.5× chain holds 1.5× — tier ≠ 1.0 boundary cell); estimate_c converts bytes to the
                 class's quantity through the per-class divisor — a pinned default in the plane's `METER_CLASSES` declaration, overridable by the card, so class caps work with no card at all (1.5.5 enforces `tokens` caps with pricing off), and a
                 client-located max_response is CLAMPED to the lane's declared max; a fan-out estimate is (for LOCALLY delivered recipients only; remote recipients are priced on their `Delivery` units — never both; §8.1 cell: Σ parent + children == the single-node figure)
                 multiplied by the recipient count resolved at Approve; the rate-card version is captured
                 NOW from the current Policy epoch. PRICING COVERAGE: a rate card present at boot must be
                 COMPLETE over every configured lane for the card's declared meter-class set (1.5.5's rule:
                 every configured lane has an entry, no entry names an unknown lane — else boot/--validate
                 FAIL with a paste-able stub); `Unpriced` is defined only relative to a PRESENT card — with no card every class prices 0, unflagged, attribution only, and `Count`-sourced kernel lines are never `Unpriced`; a meter class OUTSIDE a present card's declared set (a plane's own
                 classes) prices at 0, `estimated`, `Unpriced` on the disputes report when the class is in `unpriced_classes`
                 (`unpriced_classes` is the Migration-sealed list; `allow_unpriced`, default false in §4.7, is the boolean for classes outside it) and → Refused(Admit, Unpriced) when
                 false. Rate card ABSENT → zero prices, fee posts. The admission unit draws ALL-OR-NOTHING
                 across the principal's BUCKET CHAIN (§4.6): one slice per (bucket, dimension, scope) for
                 every capped dimension in the chain (nano-units, requests, and any `Class(...)`) — the token
                 draws are the per-class estimates, settled to actual at Meter with the delta released or
                 topped up exactly like nano-units (the draw is accounting; the token CAP is enforced
                 post-hoc exactly as 1.5.5 does, so no unit is refused earlier than 1.5.5 would refuse it). A scope-limited bucket
                 draws when its scope EQUALS the effective pool name (a fallback-pool hop draws nothing, PB-47); at Route EVERY dimension drawn on an unselected scope — nano-units, `requests`, `Class(…)` — is released (1.5.5 charges and refunds only the selected pool's buckets); "never released" applies only to the scopes the unit routed through (cell: scoped `requests` cap on a non-selected pool stays unchanged, byte-identical). An UNCAPPED
                 bucket (1.5.5 keys carry no caps) is an ATTRIBUTION bucket: unbounded slice, every posting
                 attributed, identity Σ settlements == Σ accrued. A `concurrent` lease per capped-`concurrent` bucket; a
                 frozen bucket → Refused(Admit, GroupFrozen). DOWNGRADE (1.5.5 `on_exhaust: downgrade`): when a scoped nano-units bucket is
                 exhausted and declares `downgrade_to`, the admission unit NARROWS the verified set to the
                 destinations of the `downgrade_to` pool and re-sizes the hold against them — no step
                 re-entry, because VERIFY already computed the FULL candidate set: the primary pool plus
                 every pool reachable through `downgrade_to` chains (each hop passing BOTH `pool_authorized` and `fallback_pools_authorized` on the target, bounded by a visited set — 1.5.5's cascade, governance :329-330), so the narrowed set is a genuine subset
                 of verified destinations; the cascade continues pool by pool; journaled `downgraded` on the
                 posting; no reachable pool with headroom → Refused(Admit, OverBudget). Then the Hold+Dispatched record into the HoldCell (Arrival → Admitted). A refusal
                 at steps 1–4 for a RESOLVED principal is committed BEFORE its refusal bytes leave (third wait,
                 refusal path only); the single exception is DurabilityUnavailable/StaleSlice after WAL
                 poisoning: rendered without a durable record, counted into a node-local Aggregate appended at
                 the next successful commit or at recovery, and the node drains.
5  ROUTE         egress unit ← plane.route() legs over the verified set; the cancellation token is checked at
                 every await and before every codec call (AST scan). Per leg: a Dispatched delta record (leg 1
                 lives in the hold's record) durable BEFORE the dial → transport.dial() (async) from the pool
                 (breaker per attempt) or the session's existing upstream (SessionUpstream) → the wire request
                 from VerifiedDestination + plane.encode_egress() → egress-auth decorates → lane cross-check on
                 the POST-decoration bytes → send → plane.decode_response() per frame. Response frames RELAY
                 to the client inside this step under the hold (emission clock); for open units, ingress
                 frames relay through plane.encode_ingress_frame(). Locators evaluated INCREMENTALLY at frame
                 arrival; accrual per attempt; a nested leg's Response goes to Unit.leg_results; a Client leg is
                 Deliver or AwaitReply { correlation, deadline }; an Upgrade leg upgrades after the leg's frame;
                 a PlaneRecord leg reads/writes plane records. Aborted(Client) cancels the in-flight leg
                 (best-effort); bytes already queued at cancellation are metered as a separate line.
6  METER         provisional UnitEnd computed on entry; plane.audit(&provisional) runs HERE; the usage unit
                 folds the retained locator values with the variance rule and the THREE-WAY LANE CROSS-CHECK (the request-side leg is SET MEMBERSHIP — the selected lane ∈ the located name's expansion, so a pool name never mismatches its own member — the other two legs are equality)
                 (over the legs the plane DECLARES — a leg absent by declaration is skipped; a declared leg
                 absent at runtime is MeterDisputed)
                 (AdmitFacts.lane_locator · VerifiedDestination.lane · the response lane from meter/
                 content_facts, all through the alias map) → `Usage`; the SETTLE itself —
                 Ledger::settle(HoldCell::take(), usage, &LedgerToken) → Posted — is performed by the ONE
                 exit path below (Meter computes, exit settles; exactly TWO token-sealed take() sites, the exit path and the Tick sweep; the fixture asserts there is no third). The Settle delta record — carrying the audit facts — is durable BEFORE
                 the Terminal frame leaves. (Concurrent leases are released on the EXIT PATH, every end.)
7  AUDIT         the audit unit seals the provisional end; a post-Meter divergence posts an Access/Adjust
                 amendment referencing the settle record — an effects class of its own.
exit             ONE exit path, taking the Hold from the HoldCell by CAS; the same CAS releases the unit's
                 `concurrent` leases (every end — 1.5.5's in-flight gauge decrements whatever the outcome)
                 and settles per the table. The Hold is never captured by a
                 plane-call closure (AST scan). Plane calls run under catch_unwind(AssertUnwindSafe); a panic →
                 Failed(step, PlanePanic), rendered through plane.encode_end() for 1.6.0 planes; on the `llm` plane over `http`/`sse` the connection is DROPPED with no body, as Tokio/axum did at the tag (ops :418-422) — (kernel minimal end if that
                 fails), session state poisoned, session hard-closed. Teller tasks are DETACHED; JoinHandle::
                 abort is rejected by the AST scan; the drop-guard only MARKS; the node Tick sweep is the
                 SECOND, token-sealed entry and take()s the same HoldCell → Failed(step, TaskLost) or
                 Stalled. The parent's exit cancels every outstanding nested child (bound: the child's max
                 duration; then the sweep). Abort-class failures are covered by recovery. No `?`/early exit.
```

**Settlement amount — one table, every end** (posts the lower evidence; flagged postings are on the
open-disputes report until a verdict, bounded by `dispute_max_age`):

| End | Amount | Flag |
|---|---|---|
| `Completed`, locator arrived | located usage | — |
| **`fee_count`** (every row) | KERNEL-DERIVED: 1 iff (a) the unit is an `Origin::Client` `Open`/`OneShot` unit (a provider push through `SessionUpstream` posts `fee_count = 0` — cell) whose Route selected an `Upstream`/`SessionUpstream` leg ("priced" is the KIND, not a non-zero price — with no card the fee still posts) (1.5.5's proxied request — `KernelVerb`, `Client { Deliver }`, `PlaneRecord`, `NestedPlane` units post 0 unless the card's `KernelVerb` section prices them; admin-plane cell asserts zero fee/requests postings under a non-zero fee), (b) the kernel relayed the FIRST response frame (a status/headers frame with an empty body counts — 1.5.5 bills an empty 2xx), and (c) the transport's per-frame `StatusClass` is `Success` where the transport declares one — at the FIRST response frame for `StatusAt::FirstFrame` transports, at the TERMINAL frame for `StatusAt::Terminal` transports (a stream dying before its trailer posts 0, the lower evidence; a plane `finish = Complete` against a missing trailer is `MeterDisputed`) — else the plane's `finish` at the first frame is not `Error`; the fee is DECIDED at that frame and NEVER reversed by a later abort (1.5.5: "success recorded on the 2xx headers stands" — a 2xx stream dying mid-way is 1) — where "first response frame" means the first frame RELAYED TO THE CLIENT (1.5.5's `finish_inner` reads the client-facing `resp.status()`): a buffered cross-protocol response whose upstream 2xx becomes a client 502/500 posts `fee_count = 0` and zero tokens (PB-27, PB-91); the plane's `finish` is a SECOND source — `finish = Error` against a non-error status class, or vice versa, posts the LOWER `fee_count` and `MeterDisputed` (lying-`finish` plane meta-test, §8.2). 1.5.5 bills the flat fee on 2xx only and refunds upstream 4xx/5xx, router 503 and post-admission 404; a 2xx stream dying mid-way is 1 | — |
| **`requests` dimension** (every row) | drawn at Admit for `Origin::Client` units whose verified set contains an `Upstream`/`SessionUpstream` candidate (mirrors the fee's origin rule, so a provider push consumes no client slot); settles at the DRAWN quantity for every unit whose `HoldCell` reached `Admitted` — on the scopes the unit routed through; an unselected scope's draw is released at Route (§2.2 step 4) — (every `finish_rejected` exit — governance-guard refusals incl. the pool and reachable-fallback-pool ACL 403s and the no-rate 400, malformed or non-object body, missing/unresolved name 404, unsupported path/action 404 — charges nothing; every exit after `governance_guard` — the priced-but-unrouted 404 via `finish_admitted`, rewrite 500, deadline 503, pool-empty 503, upstream and engine ends — retains the slot, PB-26) and is NEVER released (1.5.5: the admission counter is never refunded, so failures cannot escape the cap; oracle cell: N failed requests consume N slots with `fee_count = 0`); the `requests` and `concurrent` draws, are two different things: `requests` as above; `concurrent` is ONE LEASE PER CAPPED-`concurrent` GROUP (1.5.5's gauges are per group keyed by name and project no bucket — a `concurrent`-only group is enforced, a group with `concurrent` + two windows takes ONE lease; PB-22) for every non-exempt unit that reaches Admit, of any origin except Handshake, Tick (a `SessionAccrual` Tick unit draws nano-units only) and `KernelVerb` units (which draw no dimension unless the card's `KernelVerb` section prices them, in which case nano-units only, against the `kernel:admin` attribution bucket — the config-level admin's bucket, like `kernel:anonymous` and take no lease, so the admin API answers at a saturated `concurrent` cap — the §8.3 cell covers `/audit` and `/usage`) — nested, delivery, record and provider units DO count — always released on the exit path (an admin unit's set is `KernelVerb` only, so the admin cell stays green; a `concurrent` cell covers a non-upstream plane) | — |
| `Completed`, required locator absent ("required" = declared by a PRESENT card for a class it prices; with no card nothing is required and nothing is flagged) | **ZERO** — 1.5.5 bills zero when the upstream reports no usage, and so does 1.6.0 (`priced_amount = 0`, `/usage` unchanged); the accrued kernel floor is recorded as an INTERNAL `estimated` evidence line that never enters `priced_amount`, `/usage` or any 1.5.5 surface — it appears only on the 1.6.0 disputes report | `estimated`, `MeterDisputed` (internal) |
| live non-Completed end, locator arrived | located usage — EXCEPT a stream whose end carries a terminal error signal, which bills ZERO tokens as 1.5.5 does (PB-27; the located figure is internal evidence only) | — |
| live non-Completed end, locator absent | accrued kernel floor | `estimated` |
| crash-recovered, `Dispatched` present (`Recovery::materialize(&record, &RecoveryToken)`) | last checkpointed accrual (0 if none) | `recovered` |
| crash-recovered, no `Dispatched` | 0 | `voided` |
| two REPORTED evidence sources (the §4.5 variance-rule pairs) in one class family disagree beyond tolerance — for a `Locator` class the located figure is always the charge and the kernel floor is a tripwire only (§4.7) | the lower | `MeterDisputed` |
| three-way lane mismatch | the cheaper entry | `MeterDisputed` |
| accrual whose `HoldAccrual` was refused (parent already exited) | the child's own posting, backed by a synchronous slice draw at settle (overdraft if the slice is empty; on a `total` bucket it still posts, flagged `Overdraft` with no carry and the bucket stays exhausted — exposure ≤ `max_provider_push` × max price_c × `tier_bp` ÷ 10^4 nano-units per class) so the identity balances; a `late_accrual` ALWAYS posts | `late_accrual`, referencing the parent's settle |
| value delivered, settle record lost (`DurabilityLost`) | retained and re-appended | `unposted` |

**`UnitEnd`** = `Completed | Refused(step, reason) | Failed(step, reason) | Aborted(Client | Kernel { reason } |
Drain | Superseded { by }) | TimedOut(step)`, constructed only by the exit path, carrying
`posted: Result<Posted, DurabilityLost>`.

### 2.3 Session shapes (all the same loop)

- **Unit 0** is the top transport's `UNIT0_TRIGGER`. All 7 steps. If refused, `unit0_refusal` answers and
  **no session exists**. Its Route yields a duplex `Upstream` destination — the egress unit dials, Unit
  0's `EgressBody` is the first upstream frame, the kernel pairs the connections — **or** any other
  kind permitted for its origin (`Client { Deliver }`, `PlaneRecord`, `KernelVerb`) for planes with no
  upstream (an inbound broker, a receiving message exchanger, fan-out); either way `open_session(ctx)` is
  called on Completed; each later dialed upstream gets `open_upstream(dest, ctx)`. Transport handshake
  data is written into `TransportFacts`. **Handoff** (`HANDOFF { from: one-shot layer, to: session
  layer, bind: TransportFacts key }`, declared by transports whose signalling and media differ): Unit 0
  arrives on the one-shot layer; the session is bound when a connection on the session layer presents
  the bound fact (a fingerprint); mismatch is `Refused(Authenticate)` on that connection.
- **Handshake units** (`Origin::Handshake`, from a transport-native `HANDSHAKE_TRIGGER` (a TLS ClientHello-class event the transport itself frames) or from the PLANE returning `Ingress::Handshake(UnitDraft)` — the plane delimits protocol-level handshakes (the authentication and encryption-negotiation verbs of a protocol — §6 names the instances) exactly as it delimits every other unit, so no transport ever names a protocol verb; an auth `Challenge` is raised inside such a unit): Arrival
  → Decode → Authenticate (Anonymous, or challenge rounds) → Verify (`Upgrade { to }` or
  `Client { Deliver }`) → Approve = `transport:handshake` → Admit = zero-priced hold that draws no `requests` and takes no `concurrent` lease (likewise Tick units; a `SessionAccrual` Tick unit draws nano-units) — Approve: `transport:handshake` is a KERNEL-GRANTED scope for every principal including Anonymous, never a `Policy` key → Route → Meter
  `count=1` → Audit (`Access`). No step is skipped; no money moves.
- **Client units**: `Open … Close`, or `OneShot`. An **open client unit** relays ingress frames under its
  hold before `Close`; a Tick ends it at its declared max duration (`UnitDraft.max_duration ≤ max_unit_duration`, a hard bound → `TimedOut(Route)`) and never aborts otherwise; a plane whose flow outlives the bound closes and re-opens it as a new unit on the same frames: after `Ingress::Close` the kernel RE-PRESENTS the same cursor to `decode_ingress` once (the plane answers `Open` for the continuation; bounded by `MAX_NEEDMORE_FRAMES`; battery cell — request-body chunk spooling on `http`/`sse` is bounded by `request_body_max_bytes` only, never by the frame count, PB-61) — the flow-plane consequence, no kernel line per plane.
- **Provider-initiated units**: `Progress::Open`/`OneShot(UnitDraft)`; all 7 steps. **Authenticate for
  `Origin::Provider`**: the credential is the kernel's own pairing — the frame arrived on an upstream
  connection this session dialed under a Completed unit, so the principal is that dialing unit's
  principal (`CredentialFacts { issuer: Pairing }`); no client credential is involved and
  `SessionUnbound` does not apply; an upstream frame on an unpaired connection is `Discard`. Verify runs
  `plane.verify()` over the kinds permitted for provider origin. Admit: if `reply_to` resolves **to a
  unit of the same principal**, the admission unit mints a `HoldAccrual` (runtime-sealed: parent key +
  principal + generation, only while the parent's `HoldCell` is `Admitted`; the parent's outstanding
  counter gates its exit) and the unit settles into it; else its own hold sized from
  `max_provider_push`; a refused accrual (parent gone) settles as the child's own posting, `late_accrual`.
  **At the parent's exit** every outstanding `HoldAccrual` is CONVERTED into a child-owned `Hold` sized
  at `max_provider_push`, drawn synchronously (the overdraft ceiling applies; refusal trips the child's
  cancellation token) — so the `late_accrual` exposure bound is a mechanism, not an assertion.
- **Turn-level hold**: closes at the **earliest** of (a) client `Close`, (b) a `reply_to`-bearing unit
  ending with `TurnComplete`, (c) `turn_max_duration`; the parent's exit then blocks until the
  outstanding accrual counter is 0 (or the bound), then settles once; anything arriving later is
  `late_accrual`.
- **Correlation**: `(session, principal, fact_key, value) → unit_key` for units opening with
  `correlation_out`; `reply_to` from `correlates` resolves only within the same principal; unknown →
  own hold, `Uncorrelated`.
- **Interrupt**: `INTERRUPT_FACT` on an `Open`/`OneShot` performs one atomic CAS on the target's step
  state from `< Meter` to `Superseded`, trips its cancellation token (time-to-silence ≤
  `interrupt_deadline`), drops its unemitted queue (`unemitted`, not metered), settles per §2.2,
  `encode_end` renders. CAS failure is a no-op recorded on the superseding unit.
- **Pacing**: `EGRESS_PACING_FACT` (ns per frame); one emission clock per `(session, stream, direction)`;
  bounded queue; **overrun on stream transports applies upstream backpressure; on datagram transports
  frames are dropped and journaled `unemitted`**; emitted frames only are metered.
- **Tick units**: per session per `tick_interval` and per node. Session Tick: checkpoint
  `accrued_so_far` **only when the counter changed**; elapsed-time usage where priced ACCRUES INTO the session's open unit's hold (a Tick unit posts money only through a `SessionAccrual` destination; otherwise it has no lane and a zero-priced hold); **idle session time between units is unpriced by design** unless the session's bucket declares a `session_seconds` class, in which case the session Tick opens a `SessionAccrual` unit priced at the lane of the session's Unit-0 verified destination (§3.6), holds `tick_interval` × that price and settles each tick; close a bound session with a dry budget (idle, OR busy when its `SessionAccrual` unit refuses `OverBudget` — priced seconds are never accrued unmetered; cell) or a revoked principal; on an UNBOUND session the accrual is charged to the principal of the last unit, and with none the session is closed, and ANY session (bound or unbound) after `session_idle_max` with no NON-TICK unit (a `SessionAccrual` tick never resets the idle clock — cell: `session_seconds` bucket, client idle 400 s → closed at 300 s, ≤ 300 s posted) (pinned 300 s; unbound sessions cache no principal, so budget and revocation apply per unit);
  Node Tick: lease heartbeat; policy/revocation tail;
  sweep (`TaskLost`, `Stalled`); checkpoint one-shot units older than one tick; election;
  reconciliation; dispute aging; independent recompute (§4.2); peer-drain observation.
- **Nested units**: `NestedPlane(plane_key, op)` opens a child — own key, own hold (the parent's
  estimate excludes nested cost), own audit, sharing the parent's cancellation scope; the parent's Route
  blocks on the child's `UnitEnd` (bound: child max duration); separate bounded pool; `max_nest_depth`;
  boot cycle check.
- **Plane records**: `PlaneRecord { schema, op }` legs read/write kernel-held durable plane state via
  `record_put/get/scan` keyed `(plane_key, schema, key)`, verified by the trust unit, journaled
  `Access`/`Transaction`. Mutating plane admin operations are the kernel verb `plane_record_write`.
- **Fan-out**: `Client(selector)` resolves through `sessions_for`. **Aggregate mode (the only mode)**: one parent
  posting with a `recipients` `Count` line and per-recipient outcomes in the audit record; per-recipient
  `Delivery { parent }` units with own holds — **sized per recipient from the payload and drawn from the
  sender's (parent's) bucket chain; the sender pays, the recipient's policy only admits; the parent's
  `recipients` and byte lines cover locally delivered recipients only, so no recipient is priced twice**.
  Two sentences: a recipient on THIS node — whatever its bucket, the sender always pays from its own
  chain — is priced on the parent (§8.1 cell). A recipient on ANOTHER node travels in the closed peer
  envelope and is priced on a `Delivery` unit on the receiving node, drawn from the sender's chain. The
  peer envelope `{ plane_key, parent, principal, selector, payload | locator }` over `peer` (payload ≤
  `MAX_PEER_PAYLOAD_BYTES` inline; larger payloads travel **by locator** — written to a `PlaneRecord`
  and read by the receiving node); `peer` sessions and the fleet-state frames are KERNEL-INTERNAL (auth-lease authenticated), never Teller units and never a claim target (the §5 "no session without a Completed Unit 0" rule exempts `peer`).
- **Session hard-close** only on a provider-origin unit refused at `in_flight_cap` or at Admit for any money reason (the §2.2 step 0 list — the ONE source; a provider unit refused at Verify or Approve posts the floor line and the session continues), `Failed(Decode)` on stream transports, `PlanePanic`,
  `Refused(Authenticate)` on a BOUND session (a cached principal that fails re-check), `SessionUnbound`, handoff mismatch, and revocation; an ordinary credential refusal on an UNBOUND session renders and the session continues (the "wrong credential, try again on the same connection" shape); any other refused or failed unit renders and the session
  continues. **Drain**: no new Unit 0; sessions on 1.6.0 session transports pumped ≤ `max_unit_duration`, then `Aborted(Drain)`; `http`/`sse` units run to their 1.5.5 end with no deadline (PB-8); journaled. **Fleet
  coordination**: every node broadcasts its state (`serving | stale { since } | draining { reason }` — `stale` is broadcast the moment a staleness bound is crossed, BEFORE acting) to its peers over
  `peer` on each node Tick (lease-authenticated; a peer-state table aged out at `peer_table_ttl` (§4.7: `stale_serve_max + tick_interval`, so it outlives the quorum branch)); a node
  about to self-drain for lease or policy staleness reads the count of `stale + draining` peers **from
  that table** (the store is by definition unreachable; `peer` frames are authenticated by the last
  known lease keys, valid through `stale_serve_max`); **if `stale + draining` peers ≥ `drain_quorum` it
  keeps serving on its
  current slices without new draws until `stale_serve_max` (= `lease_ttl + max_unit_duration`, 630 s — every unit admitted by then settles before the store's `release_deadline` (§4.6, 1,235 s), so a slice is never spent on two sides of a partition; the peer table stays live because peers keep broadcasting), then drains (journaling `FleetOutage` every tick
  — the availability choice a quorum buys; during a `FleetOutage` any store-reachable peer FORWARDS `Policy`/revoke tail entries over `peer`, so revocation still propagates within `policy_staleness_max` + one tick wherever any node can read the store, and where none can, a revoked principal may serve for at most `stale_serve_max` — stated as the exposure), whereas an unmet quorum (or N < 2 — the quorum branch needs at least two peers) serves only for `outage_grace`; the quorum test is re-evaluated every tick, a draining peer keeps broadcasting `draining` until it exits and then ages out (the count drops); in BOTH branches a slice drawn before the outage STAYS SPENDABLE past `valid_until` (no release, no re-reserve, no `StaleSlice`) until the branch's bound — the store still accounts it drawn until `release_deadline` — cell: slice expiring mid-outage at t = 300 s; the exposure for every dimension is exactly Σ open holds on already-drawn slices — the store still accounts those slices as drawn, so no window cap is ever exceeded; cells: a partition longer than the release deadline then healed (no window over-issues); a 2-node store outage;
  in both cases without new draws — `concurrent` leases ARE draws, so in stale-policy mode they are taken node-locally against the last store-observed count, journaled, and reconciled when the store returns; a capped `concurrent` bucket may be exceeded by at most the in-flight count per node for the branch bound (`outage_grace`, or `stale_serve_max` under quorum); postings in either branch are flagged `stale_policy`, stated as the exposure — in stale-policy mode (postings flagged `stale_policy`) for `outage_grace`, journaling `FleetOutage`,
  then drains; otherwise it serves in stale-policy mode for `outage_grace` and then drains** — EXCEPT
  that a node with NO configured peers (every 1.5.5 deployment) never drains for store staleness:
  it keeps serving exactly as 1.5.5's write-behind metering did, journaling locally, admitting against
  its last-known cell state, and reconciling when the store returns (parity clause; the fleet
  branches above exist only for `peers:` deployments, a 1.6.0 addition). Drain pumps session-transport sessions
  for at most `max_unit_duration`; `http`/`sse` units are never cut (PB-8).
- **In-band upgrade** (`Upgrade { to }` leg or a Handshake unit): `SessionFacts`, `TransportFacts` and
  the cached principal are cleared; both `ArrivalRecord`s are journaled.

### 2.4 Session, transport and content facts

`SessionFacts` and `TransportFacts` are kernel-owned per-session maps **pre-allocated at `open_session`
from the declared key sets × per-key value caps**, last-write-wins. Planes write `SessionFacts` through
`facts`; transports write `TransportFacts` at `accept`/`dial`/`upgrade`/handoff; every method reads
both through `Ctx.session`. Exceeding a cap is `Failed(Decode, SessionFactsExhausted)`.

---

## 3. The contract

### 3.1 Crate graph, bounded types, type index

```
busbar-contract      traits, facts, locators, Frame, Ingress/Progress, UnitDraft, Ctx, bounded types   (plugin-visible)
busbar-caps          capability types + tokens                                                    (kernel + units only)
                     trusted base: `std` and `busbar-contract` — a capability is keyed on the contract's own objects, so it names them rather than restating them
busbar-kernel        registry + generations, Teller, pump, in-flight table, sessions, Ticks, recovery, slices/leases, drain, grammars
busbar-unit-*        auth · trust · scope · admission · cost · egress (pool) · breaker · egress-auth · transport-key · usage · ledger · audit · wal · verbs
busbar-plane-*       (one per plane)         busbar-transport-*   (one per transport, in-tree, incl. peer)
busbar-*-plugin      auth / egress-auth-scheme / store / secret / hook / export (static or dynamic); auth-lease and secret-local in-tree, mandatory
```
**Bounded types** (constants in the contract crate): `ArenaBytes<'u>` (`bytes::Bytes` is banned);
`ArrayVec<Leg, 8>` with ≤ 2 leg replies pinned; a `Vec<VerifiedDestination>` in the in-flight table (1.5.5 pools are unbounded, so the candidate set is unbounded — no `CandidateSetTooLarge`; parity clause); arena `Facts`
with `MAX_KEYS = 32`; `Ir` borrowing the frame buffer; `steps ≤ 16`; `usage_lines ≤ 16`;
`MAX_RECORD_BYTES = 512`; per-connection cursor cap 64 KiB (credential slab included; the buffer grows LAZILY and RSS counts actual bytes, never the cap) and a
node-global cursor budget (§10; `Refused(Arrival, CursorBudget)`); `MAX_NEEDMORE_FRAMES = 256` (session-transport handshakes; not body-chunk spooling, PB-61);
a client idempotency key of ANY length (1.5.5 caps nothing) is hashed streaming under the cursor cap and never truncated — no `MAX_CLIENT_KEY_BYTES`; `MAX_PLANE_SESSION_STATE_BYTES` per half and
`MAX_PEER_PAYLOAD_BYTES` — pinned at M2 from measurement; **node-global session budget** (`session_budget`:
count and bytes, derived from the 15 MB budget like the cursor budget; `Refused(Arrival, SessionBudget)`
at Unit 0); **per-unit arena = 4 KiB, RESET PER FRAME on the relay path of an open unit (each `encode_ingress_frame` / `encode_response` / transform output lives in the arena only until the frame is queued to the connection slab), reset at unit end otherwise** (pinned;
exhaustion → `Failed(step, ArenaBudget)`; relay and egress BODIES live in the connection slab / spill, never the arena, so the arena never refuses a request 1.5.5 accepted — PB-18). `Ctx.arena` is the one resource handle.

**`PlaneSessionState`**: one half per **connection** (`open_session` → the client half; `open_upstream`
→ one per dialed upstream), `Box<dyn Any + Send>` from a per-session slab, bounded per half with a
per-session cap on halves; may own `Drop` and foreign resources (the FFI transform context); cleared on
`upgrade`; poisoned and dropped on panic; dropped at close and on drain.

Type index (definitions in `busbar-contract`): `ArrivalRecord { source, port, alpn, sni, peer_cert:
Option<CertFacts>, transport_chain }` · `Refusal { step, reason (closed code), retry_after, stream:
Option<StreamId>, correlates: Option<CorrelationRef> }` (client-rendered reasons are opaque codes) ·
`Unit0Trigger`, `HandshakeTrigger`, `Handoff` · `SelectorForm` · `FinishClass { Complete, TurnComplete,
Partial, Error }` · `OpClassId`, `AdminVerbId`, `MeterClassId`, `RecordSchemaId`, `TransportId` (a registry id, never key material — `TransportKeyHandle` is the key) ·
`PlaneFacts`, `ContentFacts`, `HookFacts { permutation, restrict, veto, rewrite, tap }`, `IrPatch`, `HookView` ·
`CredentialLocator { narrowing: Option<SchemeAlt>, from_session: bool }` · `CredentialFacts { principal,
issuer, expiry, session_bindable }` · `Challenge { bytes, state, rounds_left }` · `ScopeFacts
{ resources }` · `AdmitFacts { lane_locator, max_response_ptr, input_span }` · `DestinationFacts` (§3.6) ·
`Permutation<CandidateIdx>` · `TransportEnvelope` · `Listener`, `Conn`, `StreamId`, `CloseReason` ·
`Decode`, `Encode` · `CorrelationRef { fact_key, value }` · `Labels` · `HoldCell` · `FrameCursor`,
`Estimate { per_class }`, `BucketChain`, `RoutePlan { legs }`, `UsageLocators`, `AuditFacts`,
`Decision<S>` (in `busbar-caps`) · **`LaneId`** — the
priced axis: a config-declared name per `(plane, upstream)` (1.5.5's configured lane key), the rate
card's first key, carried on `VerifiedDestination`, located in the request by `AdmitFacts.lane_locator`
and in the response by the plane's facts, all through the lane-alias map · `CapDimension
{ NanoUnits, Requests, Concurrent, Class(MeterClassId) }` — a closed **shape** over an open key: any
declared meter class is cappable (`Class(tokens)` = 1.5.5's total-token cap, the sum of the FOUR 1.5.5 classes {tokens_in, tokens_out, cache_read, cache_write} — pinned membership, so a plane's other classes never join it — i.e. the sum of every
token-family line; `Class(tokens_in)`, `Class(bytes)`, `Class(messages)` are further instances, so a
plane with no rate card still has volume control) · `BucketScope { All, Pool(name) }` (1.5.5's `pool:`, validated against the configured pools, carried in the bucket id and in the refusal text exactly as 1.5.5 prints it) · `Conn` is a cloneable
handle (reference-counted; `frames` takes one clone, `write`/`close`/`upgrade` another).

Unit traits (sealed; shapes): `Auth::resolve(..) → Decision<Authenticate>` (may yield `Challenge`) ·
`Trust::verify(.., &BreakerView, &TrustToken) → Decision<Verify>` · `Scope::approve(..)` ·
`Admission::admit(&Estimate, &Principal, &BucketChain, &AdmitToken<Admit>) → Decision<Admit>` yielding
`Hold` (all-or-nothing across the chain) or `HoldAccrual` · `Egress::route(&RoutePlan, &Pool,
&UnitToken<Route>)` · `Breaker::observe/state` · `meter(&RetainedLocatorValues, &KernelCounts,
&MeterPolicy, &LegDeclaration, &UsageToken) → Result<Metered, UsageError>` — a free function, not a
trait: the report belongs to the capability crate, and the two policy arguments are what the
variance rule and the three-way lane cross-check compare against, so a fold without them is not the
fold; `Metered` carries the usage AND the disputes · `Ledger::settle(Hold, Usage, &LedgerToken) → Posted` · `Audit::seal(..)` ·
`Verbs::execute(KernelVerb, &AdminToken)` · `Recovery::materialize(&HoldRecord, &RecoveryToken) → Hold`.

### 3.2 Plane

```rust
pub trait PlaneMeta { const KEY; const CLAIMS; const OP_CLASSES; const METER_CLASSES; const SESSION_FACTS; const CONTENT_FACTS;
                      const RECORD_SCHEMAS; const INTROSPECTION_VERBS; const INTERRUPT_FACT: Option<&str>; const EGRESS_PACING_FACT: Option<&str>;
                      const CONFIG_SCHEMA; }

pub enum Ingress  { NeedMore, Open(UnitDraft), OneShot(UnitDraft), Handshake(UnitDraft), Frame { for_: Option<CorrelationRef>, relay: ArenaBytes, facts: Facts }, Close { for_: Option<CorrelationRef>, facts: Facts }, Discard { reason: DiscardCode } }
pub enum Progress { NeedMore, Open(UnitDraft), OneShot(UnitDraft), Frame { for_: Option<CorrelationRef>, r: Response }, Terminal { for_: Option<CorrelationRef>, r: Response }, Discard { reason: DiscardCode } }
pub struct UnitDraft { op: OpClassId, body_ir: Ir, correlates: Option<CorrelationRef>, correlation_out: Option<CorrelationRef>, facts: Facts }
pub struct Response  { ir: Ir, finish: FinishClass, facts: Facts }

pub trait Plane: Plugin + Send + Sync + 'static {
    fn decode_ingress(&self, frames: &mut FrameCursor, st: Option<&mut PlaneSessionState>, ctx: &Ctx) -> Result<Ingress, Decode>;
    fn encode_egress(&self, u: &Unit, dest: &VerifiedDestination, st: Option<&mut PlaneSessionState>, ctx: &Ctx) -> Result<EgressBody, Encode>;
    fn encode_ingress_frame(&self, u: &Unit, f: &Frame, dest: &VerifiedDestination, st: Option<&mut PlaneSessionState>, ctx: &Ctx) -> Result<Option<ArenaBytes>, Encode>;
    fn decode_response(&self, frames: &mut FrameCursor, dest: &VerifiedDestination, st: Option<&mut PlaneSessionState>, ctx: &Ctx) -> Result<Progress, Decode>;
    fn encode_response(&self, r: &Response, st: Option<&mut PlaneSessionState>, ctx: &Ctx) -> Result<ArenaBytes, Encode>;
    fn encode_refusal(&self, refusal: &Refusal, draft: Option<&UnitDraft>, st: Option<&PlaneSessionState>, ctx: &Ctx) -> Result<ArenaBytes, Encode>;   // deliberately &: a refusal never mutates codec state (a sequence-numbered protocol cannot advance its counter on a refusal — a stated constraint of the litmus)
    fn encode_end(&self, u: &Unit, end: &UnitEnd, st: Option<&mut PlaneSessionState>, ctx: &Ctx) -> Result<Option<ArenaBytes>, Encode>;
    fn authenticate(&self, u: &Unit, ctx: &Ctx) -> CredentialLocator;
    fn verify(&self, u: &Unit, ctx: &Ctx)       -> DestinationFacts;
    fn approve(&self, u: &Unit, ctx: &Ctx)      -> ScopeFacts;
    fn admit(&self, u: &Unit, ctx: &Ctx)        -> AdmitFacts;
    fn route(&self, u: &Unit, ctx: &Ctx)        -> RoutePlan;
    fn meter(&self, u: &Unit, r: &Response, ctx: &Ctx) -> UsageLocators;
    fn audit(&self, u: &Unit, out: &UnitEnd, ctx: &Ctx) -> AuditFacts;   // { op_class, finish }; at Meter entry with the provisional end;
                                                                          // the DRAFT's op prices; an op_class differing from the draft → MeterDisputed;
                                                                          // Response.finish is the fee's second source; AuditFacts.finish differing from it → the lower fee_count, MeterDisputed
    fn plane_facts(&self, verb: AdminVerbId, ctx: &Ctx) -> Result<PlaneFacts, Decode>;
    fn content_facts(&self, u: &Unit, r: &Response, ctx: &Ctx) -> ContentFacts;
}
pub trait SessionPlane: Plane {
    fn open_session(&self, ctx: &Ctx) -> PlaneSessionState;
    fn open_upstream(&self, dest: &VerifiedDestination, ctx: &Ctx) -> PlaneSessionState;
}
```
The registry requires `SessionPlane` iff any claimed transport declares `SESSION = true`. If
`encode_refusal` or `encode_end` fails, the kernel emits a kernel-owned minimal end. `Unit { key,
origin, session, reply_to, byte_counts, frame_counts, leg_results, .. }` is kernel-built. `Ctx { clock,
config, session, transport, labels, arena }`. Minted secrets: `SecretOnce` placeholder (128-bit nonce
bound to the unit and a declared target location), exactly one occurrence at that location, else
`Failed(Encode, SecretPlaceholder)` with the mint reversed; never in `ContentFacts`.

### 3.3 Claims, selectors, locations, the JSON span grammar

```
Claim            = { transport: key, selector: Selector, scheme: auth scheme key (+ declared alternatives),
                     idempotency: Option<{ location: Location, replay: Reference | Body }> }
Selector         = ExactPath(p) | PrefixOneLevel(p) | Sni(host) | ClientCertSubject(dn) | PathPattern([Lit(s) | Var | Tail]) (1.5.5's `/{name}/v1/…`, `/{provider}/{model}/v1/…`, `/model/{id}/converse`, `/v1beta/models/*rest` — one boot cell per 1.5.5 route) | HeaderExact(name, value) | HeaderPresent(name) | HeaderPrefix(name, prefix) | PathSuffix(s) | PathContains(s) (the three forms 1.5.5's protocol-detection ladder needs — `anthropic-version` / `x-api-key` / `x-goog-api-key` presence, `AWS4-HMAC-SHA256` prefix, `/v1/chat/completions` suffix, `:generateContent` / `/converse` contains — pinned as the 14-rung ladder in PB-30; `overlaps` treats a Present/Prefix/Suffix/Contains claim as overlapping any claim on the same header or path family) | StreamName(s) | Alpn(a) | Port(n)
ArrivalLocation  = Header(name) | Query(name) | FirstFrameJsonPointer(ptr) | ClientCert | Signed { over: Url | Body | Both }
                 | HandshakeFrames { max_frames, max_bytes }                       // the ONLY forms an auth scheme's LOCATIONS may use
Location         = ArrivalLocation | UnitJsonPointer(ptr)                          // UnitJsonPointer: idempotency only; kernel-extracted from the Ir span
```
Overlap is checked ACROSS planes; within one plane the claims form an ORDERED pattern set with sealed most-specific-wins precedence (`Lit` before `Var`, longer before shorter, pools before lanes — the 1.5.5 order; the boot cell asserts it). The kernel owns `overlaps` (for `PathPattern`, per segment: `Var` overlaps any `Lit`, `Tail` overlaps any suffix — conservatively), **total over the cross-product of forms** (cross-form pairs conservatively
overlap); reflexivity and symmetry asserted; a boot cell per form pair. **An overlap is RESOLVED by the sealed order before it is refused**: two claims of DIFFERENT precedence are settled by most-specific-wins, and sealing records the pair and its winner; only an overlap at EQUAL precedence — where the order has nothing to say and the route would fall to declaration accident — is a boot refusal; two claims whose SCHEME SETS (declared scheme plus its narrowing alternatives; a claim declaring no scheme has no set and is compatible with every claim) are disjoint never overlap at all, because one request carries one credential. Anchored beats floating: `PathSuffix(s)` matches a strict subset of `PathContains(s)` and outranks it where the length score ties. The five shipped planes' 49 claims seal on this rule with 209 resolved pairs and no refusal. Masking per
form: span forms → same-length fill; `ClientCert` → nothing masked; `Signed` → the signature span only;
`HandshakeFrames` → bounded prefix. **JSON is the one serialization the kernel understands, as a closed
grammar**: a zero-copy, non-allocating span scanner (M1) resolves pointers over the scanned prefix up to
the deepest pointer; its cost is a §10 row.

**A claim's selector is a compile-time constant, never a registration-time value derived from config.**
Where a plane's mount is fixed to a single canonical address by design, that address is the literal in
its `Selector`, and an operator-configured canonical address is checked against it at config validation:
naming any other path is a boot refusal, not a silent rebind. There is no selector form that resolves a
configured string at registration.

### 3.4 Transport (in-tree, async)

```rust
pub trait TransportMeta { const KEY; const SELECTOR_FORMS; const EGRESS_SELECTOR_FORMS; const COMPOSES_OVER: &[&str]; const HANDOFF: Option<Handoff>;
                          const SESSION: bool; const SESSION_BOUND: bool; const UNIT0_TRIGGER; const UPGRADES_TO: &[&str];
                          const HANDSHAKE_TRIGGER: Option<HandshakeTrigger>; const TRANSPORT_FACTS: &[&str]; const DECODES_PAYLOAD: bool; const STATUS_CLASS: Option<StatusAt { FirstFrame | Terminal }>; }   // STATUS_CLASS: the transport carries a closed `StatusClass { Success | ClientError | ServerError | Other }` as PER-FRAME meta on the first response frame (`FirstFrame`, e.g. a status line) or on the terminal frame (`Terminal`, e.g. a status trailer) — never a session-level fact, so composed layers cannot overwrite it; a composed transport inherits the lower layer's status leg; a transport without one contributes no status leg and the plane's `finish` is the fee's sole source — accepted and stated
type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;   // the one boxed future per call is an alloc-gate exclusion
pub trait Transport: Plugin + Send + Sync + 'static {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord;
    fn listen(&self, cfg: &TransportConfigView, keys: &TransportKeyHandle) -> Fut<'_, Listener>;
    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn>;
    fn dial<'a>(&'a self, dest: &'a VerifiedDestination, keys: &'a TransportKeyHandle) -> Fut<'a, Conn>;
    fn frames(&self, conn: Conn) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;
    fn write<'a>(&'a self, conn: &'a Conn, stream: StreamId, bytes: ArenaBytes<'a>) -> Fut<'a, usize>;   // copies into a per-connection slab; returns bytes queued
    fn upgrade<'a>(&'a self, conn: Conn, to: &'a str, keys: &'a TransportKeyHandle) -> Fut<'a, Conn>;
    fn close(&self, conn: Conn, reason: CloseReason);
    fn unit0_refusal<'a>(&'a self, conn: Conn, refusal: &'a Refusal, bytes: ArenaBytes<'a>) -> Fut<'a, ()>;
}
```
`TransportError` is closed and mapped 1:1 onto `UnitEnd` reasons. The **egress unit** owns the pool per
`(transport, destination)`; the **breaker unit** owns trip/cooldown/fast-fail per `(pool, destination)` — a `BreakerCell` per pool member, independent per pool; only `max_concurrent` and the lifetime `max_requests` are lane-global (PB-83) — **and the
per-destination lifetime request budget** (1.5.5's `ModelCfg.max_requests`, default −1 = unbounded, a
`total`-window cap scoped to the DESTINATION, not the principal): one unit is spent AFTER the upstream 2xx headers (`engine/mod.rs:2163-2172`, not the client-facing status) and reversed only on the rows the inventory refunds (PB-27); an
exhausted destination is `DestinationBudgetExhausted` — excluded from the walk (PB-3), never "ordered last" (the set
proceeds through Admit; all exhausted → `Failed(Route, DestinationBudgetExhausted)` after the `requests`
draw, as 1.5.5's 503 after its charge); the remaining budget is exposed to hooks as the `budget_remaining`
fact; journaled as `Slice` lines on the destination's own bucket; oracle cells: exhaustion, failover on
exhaustion, refund on body failure, pick order with `budget_remaining`.
**Composition**: the top transport owns `KEY`, claims, `SESSION`, `SESSION_BOUND` and Unit 0; lower
layers yield frames and are never claim targets; Locations resolve against the bottom layer's
`ArrivalRecord`, re-resolved after `upgrade`; a `HANDOFF` declares the signalling→session binding.
**Key material**: the **transport-key unit** resolves keys through the secret plugin at
`listen`/`dial`/`upgrade` (journaled `Access`) and hands an opaque `TransportKeyHandle`. Backpressure
is bidirectional with a bounded per-unit frame buffer.

### 3.5 Capability types (sealed by token, not by visibility)

| Type | Built only by | With |
|---|---|---|
| `Decision<S>` | the unit owning step `S` (kernel for `Arrival`/`Decode`/`Encode`) | `&UnitToken<S>` |
| `VerifiedDestination` | the trust unit | `&TrustToken` |
| `Usage` | the usage unit | `&UsageToken` |
| `Hold` | the admission unit into the `HoldCell`; **`Recovery::materialize` from a journal record** | `&AdmitToken<S>` / `&RecoveryToken`; `#[must_use]`; no `Drop` impl; cell-linear |
| `HoldAccrual` | the admission unit while the parent's cell is `Admitted` and the principal matches | `&AdmitToken<Admit>`; runtime-sealed |
| `Posted` | `Ledger::settle(Hold, Usage)` | `&LedgerToken` |
| `DurabilityLost` | the WAL unit on an observed sync failure | `&DurabilityToken` |
| `AuthDecoration`, `SecretSlot` | the egress-auth unit | `&EgressAuthToken` |
| `TransportKeyHandle` | the transport-key unit | `&TransportKeyToken` |
| `SecretOnce` | the verbs unit | `&AdminToken` |
| `Origin`, `IdempotencyKey`, `SessionId`, `UnitEnd` | the kernel / the exit path | private seal |

Tokens are `!Clone + !Copy`; a fresh token per step call, dropped at return. Fixtures: `UnitToken<Meter>`
cannot build `Decision<Admit>`; the Teller cannot construct `Hold` or reach `RecoveryToken`; two holds
into one cell fail (the cell is a state machine); `forget`/`drop`/`leak` of a `Hold` is refused; a
`Hold` captured by a `catch_unwind` closure is refused. **Two-sided replay canary** per cell: drafts
accepted == holds + accruals-into-parent == settlements (incl. `late_accrual`) or aggregated declines;
every settlement references a prior hold.

### 3.6 Destinations and egress

```
DestinationFacts    = { kind: Upstream { transport, host, lane } | SessionUpstream { upstream: UpstreamIdx (returned by `open_upstream`; in range for this session; ≤ `MAX_SESSION_UPSTREAMS` = 8, inside the session budget), stream: Option<StreamId>, lane: LaneId (copied from the paired upstream at `open_upstream`; a session that dialed nothing carries the card's `*` row for `SessionAccrual` only — it has no provider units by definition) }
                              | Client { selector, mode: Deliver | AwaitReply { correlation, deadline } } | KernelVerb { verb }
                              | NestedPlane { plane, op } | SessionAccrual { lane } | PlaneRecord { schema, op } | Peer { node, selector } | Upgrade { to } }
Permitted kinds by origin: Client → all except Peer (reached only through `sessions_for`) and SessionAccrual (Tick only); Provider → Client(session), SessionUpstream, NestedPlane, PlaneRecord;
                           Arrival → none (Unit 0 is a Client unit; an Arrival subject is a refusal only); Bootstrap → KernelVerb { bootstrap } only; Handshake → Upgrade, Client { Deliver }; Tick → none (a Tick unit is zero-priced; its hold-sizing max over ∅ is 0 and the lane cross-check does not run), except `SessionAccrual { lane: the session's Unit-0 `Upstream` lane, or the card's `*` row for `session_seconds` when Unit 0 dialed nothing (a session that dialed nothing has no provider units by definition) }` when a `session_seconds` class is declared; Nested → Upstream, SessionUpstream, NestedPlane (depth < max_nest_depth), PlaneRecord, Client { Deliver }; Delivery → Client { Deliver }, Peer, and Upstream (a scatter to N upstreams is N `Delivery` children with per-recipient holds from the sender's chain, so the 8-leg bound per unit never limits fan-out) (neither may reach KernelVerb or SessionAccrual).
VerifiedDestination = sealed after the trust unit's rule per kind:
    Upstream        allow-list · the network guard (resolve-then-pin against the allow-list; the hardcoded metadata denylist; the `base_url + path` re-check) runs here, BEFORE any transport `dial`, never inside a transport · transport key resolves · lane permitted for the draft's op class (the located name may be a pool, expanded to member lanes)
                    · unit price ≤ max (1.6.0 cards only) · breaker consulted
    SessionUpstream the session's paired upstream exists (stream in range) and the session's principal is the unit's
    Client          selector resolves within the session, or through `sessions_for` (Peer for remote nodes); the recipient's
                    policy admits delivery from the sender's principal; AwaitReply deadline ≤ turn_max_duration
    KernelVerb      the principal holds the verb's admin scope (always checked — satisfied for `Principal::Anonymous` when `admin_auth: []`, 1.5.5's open-admin posture, PB-36; the data-listener verbs `/healthz`, `/stats`, `/metrics`, `/metrics/hooks` carry a kernel-granted scope and 1.5.5's own auth rule, PB-43); posture rules of §4.7; read_* are pinned at
                    0 and never refused for budget or breaker
    NestedPlane     the child plane is registered · depth < max_nest_depth · the op class is permitted for the principal
    PlaneRecord     the schema is declared by the calling plane · the op is within the schema's declared ops · size ≤ cap
    Peer            the node holds a live lease at the current epoch · never from a claim
    Upgrade         `to` ∈ UPGRADES_TO of the current top transport · at most one upgrade in flight per connection
EgressBody     = { envelope: TransportEnvelope, body: ArenaBytes, auth: SchemeKey }
AuthDecoration = Decorate { envelope_fields (closed allow-list; never a lane-locator field), body_signature, slots: [SecretSlot] }
               | Handshake { max_frames, max_bytes }
```
The egress-auth unit substitutes every `SecretSlot` itself; the envelope must still equal the
`VerifiedDestination`; the lane cross-check re-runs post-decoration. A hook that changes the selected
destination is permitted only under `may_change_destination`; the pre/post head is in the audit record.
**1.5.5 candidate ordering** — the natives named by `strategy:` AND the inline weighted (SWRR) floor every 1.5.5 deployment gets when it names none — (candidate order walked by the failover loop) are exactly such hooks: at
`Migration` every hook present in the 1.5.5 config, every `strategy:` native, and the implicit SWRR floor (registered as an in-tree hook at `Migration`) is sealed `may_change_destination = true` (and
`max_priced_delta = unbounded`), so pick order stays byte-identical (oracle cell).
`expose()` in the auth, egress-auth and transport-key units only.

### 3.7 What Rust enforces, honestly

| Property | Mechanism | When |
|---|---|---|
| A plugin cannot name the kernel, a capability, a unit, another plane or a transport | manifest allow-list | CI |
| A pure-kind plugin cannot perform I/O (own crate: scan; dependencies: `cargo metadata` + review); I/O kinds are bounded by signature, deadline, `Access` entries and review | source denylist; blocking pool | CI + runtime |
| A plugin cannot build a decision / destination / usage / hold / accrual / decoration / key handle / posted | token-sealed constructors. The token is `busbar-caps`', and the manifest allow-list refuses a plugin crate that names that crate at all. The contract's sealing trait is public in `plugin` — it must be, since `busbar-caps` implements it and sits above the contract, and Rust cannot say "implementable by exactly one other crate" — so it is kept off the contract's ROOT surface and the `kernel-seal-impls` scan forbids implementing it in-tree outside `busbar-caps` (ten files are a named ratchet; two of them are plane crates that may not name `busbar-caps` and stay forgeable until the contract offers a seal a plane may name). An out-of-tree plugin CAN implement it; a loaded plugin is trusted code, so that is not a line drawn here | compile-time for caps-token holders + CI scan (in-tree) |
| Every trait method implemented; no default bodies; one base trait; sealed unit traits; feature-invariant | trait shape + AST scan | compile-time + CI |
| Object safety | fixture per kind | compile-time |
| Every path takes its `Hold` exactly once | `HoldCell` state machine + CAS; no `?`/early exit; no capture in `catch_unwind`; no `abort` | runtime CAS + lint |
| Every path *actually* settles, and every unit has a hold | two-sided canary; mutation on the seven files | CI |
| Pure plugins are pure over their inputs (own crate) | interior-mutability scan; determinism meta-test | CI |
| Claims unique, non-overlapping, decidable | closed grammar; `overlaps` total; xtask + boot | CI + boot |
| No kind/dialect/plane logic in the kernel or §1–§4/§10 | lean-core scan (literal comparison) + doc scan | CI |
| No stub facts | no-stub scan with reviewed allow-list | CI |
| Secrets never leave the three units (pure kinds); transports in-tree in the TCB; dynamic kinds bounded by the signature | `expose()`/`SecretOnce`/`SecretSlot` scans; canary grep | CI + oracle |
| Panics and stalls post | `catch_unwind`; guard marks; Tick sweep; deadlines on I/O kinds; `panic = "unwind"` set at M1 and required by `profile-lock` (a dev-tree script; it does not check `panic` today) | runtime + gate |
| Plugin crates carry no `unsafe`; no self-mount (declared confined routes are kernel-mounted, PB-31) | `forbid(unsafe_code)` scan; ABI surface scan | CI |

---

## 4. Money

### 4.1 One journal, fixed-size records

Records: `Hold+Dispatched`, `Dispatched` delta, `Settle` delta (carries audit facts), `Adjust`, `Slice`,
`Lease` (concurrent), `Policy`, `Checkpoint`, … each ≤ `MAX_RECORD_BYTES` with an overflow
continuation; **a torn tail is truncated at recovery to the last record whose `hash` verifies**.
`JournalEntry { seq (presentation only), node, node_seq, lease_epoch, policy_epoch, prev_hash, body_hash,
hash, subject, key_hash, class, steps ≤16, usage_lines ≤16 (meter_class, quantity, source, estimated),
priced_amount (nano-units, i128, post-tier), pre_tier_amount, tier_bp, fee_count, currency, rate_card_version,
bucket_chain_ref, window_start, wall, mono, audit: AuditFacts, correlation_hash, refs: [(node,
node_seq, hash)], versions }`. **No client-supplied bytes are in the entry**: the client idempotency key
is stored as `H(client_key)` (`claim_key` keys on the hash); the correlation label is hashed. Hashing:
`body_hash` on the unit's thread; `hash = H(version ‖ node ‖ node_seq ‖ prev_hash ‖ body_hash)` in the
sequencer. `subject = Principal(pseudonym) | Arrival | Node | Aggregate`. `class = Transaction | Access |
Slice | Lease | Policy | Checkpoint | Reconciliation | Migration | Bootstrap | Purge | Load |
ChainBreak | StoreRestore | FleetOutage`. `append_batch` idempotent on `(node, node_seq)`.

### 4.2 Chains, checkpoints, signing, anchoring, retention, reconciliation

Each node seals its own chain at WAL time. A `Checkpoint` — by the winner of `elect_checkpoint` every
`checkpoint_entries` or `checkpoint_interval` (§4.7) — cross-links every head; seals per `(bucket,
dimension, scope)` totals (**budget, Σ
drawn, Σ released, Σ settled, Σ open holds, Σ adjustments, Σ unreconciled, Σ overdraft carried in/out,
oldest open hold age, open-dispute count, oldest dispute age, Σ disputed**), the `backup_watermark`,
and the store `Seq` high-water; is signed via the secret plugin's `sign`; is anchored through an export
plugin's `ANCHOR`. The anchor sink must lie outside every node's write authority — a trust assumption
stated, not enforced; the default local-file anchor is self-attestation and the ledger endpoint (PB-16) reports it with an
alarm; `verify` reads the head back; `anchor_failures_alarm` consecutive anchor failures alarm and are
journaled.
`verify(since = last anchored checkpoint)` = node chains verify (body and chain hash), checkpoints
resolve and validate, `Seq` monotonic per node, anchored head matches, and **the one identity, per
`(bucket, dimension, scope, window_start)`, as a delta from the last sealed `Checkpoint` totals**:
**Δ settlements + Δ open holds + Δ open-slice remainders + Δ unreconciled + Δ adjustments − Δ overdraft
carried ± Δ cross-window transfers == Δ drawn from the store** — **an unreconciled amount is a MOVE out
of settled, never a parallel tally**: booking it is `unreconciled += A; settled -= A` on the same figure,
so the identity closes with no special case and nothing is reported as settled that the store has not
confirmed (for the open window, `Δ drawn` is the
window cap minus store remaining minus the checkpointed figure; closed windows must show Δ = 0 after
their last transfer; adjustments release headroom to the store only inside the open window, otherwise
they are pure ledger reversals; an attribution bucket's identity is Σ settlements == Σ accrued). **Independent recompute** on the node Tick: for every
posting since the RECOMPUTE WATERMARK — the last recomputed `(node, node_seq)`, carried in the `Reconciliation` entry, never "since the last checkpoint" (at the headline rate a checkpoint is 42 ms old and would cover 4 % of postings); the watermark must reach the journal head every tick (cell: a hand-corrupted `priced_amount` older than the last checkpoint still alarms) — `Σ quantity × price` is recomputed from the `Policy` sealed at the
posting's `policy_epoch` — the card at `rate_card_version`, `per_request_fee` (which prices the fee
line) and the bucket's `tier_bp` are all sealed there — and compared to `priced_amount`; divergence
alarms; the recompute applies clause 2 origin rule to the fee line (0 for non-client origins); on a no-card deployment the fee line is what the recompute checks (asserted by the no-card cell).
`verify` runs every T (default 24 h) writing a `Reconciliation` entry. WAL loss is a `ChainBreak`.
**Retention** (any store) purges a segment only when **all** hold: older than an anchored checkpoint;
below the `backup_watermark`; no open dispute or adjustment references it; and either an acked export of
the segment (`Export::receive(Segment)`) or a dual-controlled `retention: discard`. When no backup is
configured, `backup_watermark := the anchored head`. **Retention posture is sealed at
`Bootstrap`/`Migration` from the config**: a config that names NO store (1.5.5's `memory`, which
retained nothing across a restart) is sealed `retention: discard-after-anchored-checkpoint` with NO boot warning and no disk-driven behaviour unless `data_dir` is written (PB-13/15/17; the numbers below apply to a `data_dir` deployment) — segments
older than an anchored checkpoint are discarded — an entry referenced by an open dispute is first COPIED (≤ 512 B) into the dispute register so the segment can go and admission never stops on unresolved disputes — at the EARLIER of `wal_capacity` and a free-space low-water mark (`wal_free_min` = 2 × segment size = 128 MiB, pinned, sealed in `Policy`; the boot warning quotes the effective capacity; cell: disk smaller than `wal_capacity`, two fills, continuous admission)
(default 4 GiB, pinned), journaled `Purge`, alarmed, on the ledger endpoint (PB-16), Appendix A — strictly more record than
1.5.5 kept, and a zero-config node never stops admitting; a config that names an explicit store keeps
the fail-closed rule ONLY when `data_dir` is written (PB-15: a migrated config has no WAL and never refuses for durability): keep-on-disk under the high-water refusal with an alarm at 80 % naming the two
ways out (configure an export, or dual-control `retention: discard`) — an operational requirement
named in §10, never a silent purge. **Migration** reads the 1.5.5 chain head (through the
store adapter's `legacy_audit_head` — an EMPTY head, as the memory store and any ABI-2 `Unsupported` answer give, seals `Migration` at a zero opening balance, never a refusal) and balances (`legacy_cells_read`), seals `Migration`, posts an
opening-balance entry per bucket at the named card version. The journal is a
financial record exempt from erasure; content never enters it. **Pseudonyms**: `principal = SIV-AEAD
(sub_key(principal_id), principal_id)` — deterministic and invertible with the sub-key (so `/usage` shows
1.5.5's key ids), unlinkable after the sub-key is dropped; sub-keys under the deployment keyset in the
secret plugin; rotation and escrow follow §4.7; key loss is treated as erasure and journaled.

### 4.3 Durability, WAL, fail-closed

- **Waits per one-shot unit: two** (`Hold+Dispatched` before the dial; `Settle` before the `Terminal`
  frame); one more per further leg or attempt; a third on the refusal path for a resolved principal.
  Append-only segments preallocated INCREMENTALLY (segment size 64 MiB, pinned; `wal_capacity` is a high-water cap, never a boot-time allocation — boot cell: serves with less than `wal_capacity` free); `pwrite` + `fdatasync` per group-commit batch (window target 250 µs; measured at M2); the
  sequencer pipelines; no memory-mapped writeback. **Any sync error poisons the segment**:
  `DurabilityLost` immediately; batches *n* and *n+1* re-appended to a fresh segment or the node halts.
- **Shipping** is segment-level batched `append_batch`; un-acked records are never overwritten; WAL
  capacity ≥ backup RPO; above the high-water mark → `Refused(Admit, DurabilityUnavailable)` (a `data_dir` deployment only, PB-15). **Memory
  store**: the WAL is the system of record; boot replays from the last `Checkpoint` plus the tail;
  retention per §4.2. **Durable stores**: retention per §4.2; on `StoreRestore` every node re-ships from
  `heads(node)` before `reseal_epoch_floor`; a restore below the `backup_watermark` is a `ChainBreak` by
  definition. A store's required record rate for a deployment is ≥ 2 × its unit rate (boot warning ONLY when `peers:` or `data_dir` is written; otherwise a ledger-endpoint line, PB-41).
- **Budgets (measured at M2, re-baselined once)**: group-commit wait ≤ 0.5 ms p99 and ≤ 0.2 ms p50; ≤ one
  `fdatasync` per wait at concurrency 1; slice draw ≤ 5 ms p99 and ≤ 1 per 1,000 units; `claim_key`/
  `replay_put`/`session_put` ≤ 5 ms p99; shipping lag ≤ 1 s p99; emission queue ≤ 200 ms of frames.
- WAL failure at Admit → `Refused(Admit, DurabilityUnavailable)` (§2.2 exception). At a further leg →
  `Failed(Route, DurabilityUnavailable)`. At Meter → `Terminal` still sent; `posted: Err(DurabilityLost)`;
  retained in a bounded node buffer; re-appended; `unposted` on the disputes report; the node drains.
  Disk full = WAL failure. Store unreachable → §2.3's fleet rule. `claim_key` unreachable → fail closed
  for keyed units.

### 4.4 Holds, keys, recovery

- Key = `(principal, op_class, target resource locator, H(client_key))` when the claim declares a
  location and the kernel finds one (1.5.5 scopes a rotate's token to the rotated key so a create and a
  rotate sharing a header never replay each other — oracle cell), else kernel-minted. Client keys: `claim_key` synchronously before the hold → `Claimed`; `HeldBy` →
  `Refused(Admit, Replayed { token })` or `Refused(Admit, InFlight)`. `replay: Body` (credential-minting
  verbs) returns the post-substitution bytes from the replay cache; for the two 1.5.5 replayable
  operations (key mint, key rotate) the cache is the 1.5.5 one — PER NODE, in process, TTL 600 s, keyed
  `(actor, header)` for mint and `(actor, "rotate:{id}:{k}")` for rotate, no body hash (parity clause:
  a retry on another node mints twice exactly as 1.5.5 did); the new credential-minting verbs use the
  store-backed sealed cache at `min(dispute_max_age, max(600 s, longest finite cap window + max_unit_duration))`;
  no other legacy operation reads a cached body.
  Liveness = one window. Recovery and lease expiry call `void_claims`.
- Recovery on boot for every open hold whose `lease_epoch` < current, regardless of age: the recovery
  module materializes the `Hold` from its journal record (`RecoveryToken`) and settles through
  `Ledger::settle` per §2.2's table; `kill -9` at every durability point, between every adjacent pair of
  steps, between `claim_key` and the hold, and between legs is a battery.
- `Hold::accrue` → `Exhausted` at the cap → one top-up from the slice; slice empty → one synchronous
  `reserve`; refused → **the unit continues to `Terminal`, posts the full amount, `Overdraft`**; the
  carried overdraft **reduces the next window's admissible budget**: `reserve` deducts the prior
  window's carried overdraft before returning the first slice, and the opening `Checkpoint` carries
  `overdraft_carried_in`. Overdraft applies to every dimension that accrues mid-unit (nano-units and the
  class dimensions; `requests` and `concurrent` are known at Admit). **A `total` window never rolls, so
  it admits no CARRIED overdraft**: a refused `reserve` on a `total` bucket ends a 1.6.0 session-plane unit `Aborted(Kernel {
  OverBudget })` at the point of exhaustion — never an `http`/`sse` unit, which 1.5.5 admits once and runs to its end (PB-58) — (emitted bytes metered, posted exactly; the excess over the drawn slice is journaled as an `Overdraft` posting with `carried_out = 0` so it enters the §4.2 identity — a §8.3 cell). The **overdraft ceiling** belongs
  to the **capped `(bucket, dimension, scope)` whose `reserve` was refused** — enforced on every capped
  bucket in the chain; attribution buckets never refuse and have none — and is a **hard bound**: new
  units → `Refused(Admit, OverdraftCeiling)` (never on a Migration-sealed bucket, PB-58); a 1.6.0 session-plane unit already in flight whose accrual reaches the ceiling
  ends `Aborted(Kernel { OverdraftCeiling })` (an `http`/`sse` unit posts `Overdraft` and continues, PB-58) (cancellation token; `encode_end` renders; emitted bytes
  metered), so the maximum exposure is the ceiling plus one accrual step; released by a dual-controlled
  `set_overdraft_ceiling`.
- Failover only before the first byte; accrual per attempt; abandoned attempts explicit.

### 4.5 Quantities and pricing

- `Usage` is lines of `(meter_class, quantity, source, estimated)`. **Closed quantity sources**:
  `Locator { direction, ptr }` (incremental) · `KernelBytes ÷ divisor` (floor, `estimated`) ·
  `KernelFrames × factor` (exact) · `TransportUnits` (only where `DECODES_PAYLOAD`; a transport that
  decodes a timestamped payload reports units from timestamp deltas ÷ its clock rate) ·
  `KernelElapsedMono` · `Count` (kernel-derived) · **`PlaneCount { content_fact_key }`** — a cardinality a plane surfaces as a declared `CONTENT_FACT` (calls, objects, rows, queries, messages — never `recipients`, which is the kernel's `Count` through `sessions_for`), priced only against a config-declared class and paired with a kernel-derived companion line in the SAME UNIT where one exists (`KernelFrames` for per-frame cardinalities, `Count`) so the variance rule engages; where no same-unit companion exists (objects, rows, queries) the line posts `estimated` on the disputes report under a ONE-SIDED implausibility bound against a bytes/frames proxy of the `locator_floor_ratio` shape (never an equality check); the under-reporting-plane meta-test is red through the pair, the over-reporting-`objects` meta-test through the bound.
  **A peer-supplied handshake value (a negotiated frame timing) is never a sole evidence source**: any
  `Count × TransportFacts-key` quantity must carry a second kernel-derived line in the same class family
  (`KernelElapsedMono`, or `TransportUnits` where decoded) so the variance rule engages. **Variance
  rule**, stated per source pair: `PlaneCount` or `Count × TransportFacts` versus its kernel companion — disagreement beyond the per-class tolerance (`variance_tolerance`,
  §4.7; a rate card may tighten it per class) post the lower, `MeterDisputed`; `KernelBytes` is
  cross-checked against the socket counter.
- **Numeric contract, five numbered clauses — clauses 1–4 are 1.5.5's pricing law (`cost.rs`;
  `billing-unified.md` in the dev tree restates it), with a changed storage layout; clause 5 is new in
  1.6.0.**
  1. *Rates*: integer nano-units per quantity (config micro-units × 1000, `f64::round` once at policy
     load; NaN/negative clamp to 0); base unit price depends on `(lane, meter_class)`; an **extras table**
     (open keys) adds further meter classes; budget caps are configured in cents (1.5.5's unit) and LIFTED to nano-units at policy load (`cap × 10^7`) for the ledger's draws and slices, but the ADMISSION COMPARISON is 1.5.5's — derived spend truncated once to cents, plus the fee lookahead, against the cap in cents (parity clause) — so no window ever refuses earlier or later than 1.5.5.
  2. *Storage*: `pre_tier_amount` = Σ over the posting's usage lines of quantity × unit price, in
     nano-units, INCLUDING the flat fee as its own usage line (class `fee`, quantity `fee_count`, unit
     price `per_request_fee` cents × 10^7 for `Origin::Client` `Open`/`OneShot` units whose Route selected an `Upstream`/`SessionUpstream` leg ONLY (§2.2 (a)) and 0 for Handshake, Tick (incl. Tick units routing `SessionAccrual`), Nested, Delivery and Provider units — one fee per client request, as 1.5.5 (oracle cell) — 1.5.5's key, clamped as there; the fee consumes budget
     exactly as in 1.5.5); currency is a 1.6.0 addition (one per bucket; mixing is a boot refusal); `tier_bp` likewise: one per chain, mixing is a boot refusal.
  3. *Projections* (read only, truncating once over the summed nano-units incl. the fee line — since the
     fee line is an exact multiple of 10^7 this equals 1.5.5's "truncate usage, then add fee"): cents =
     `Σ nanos ÷ 10^7`; micros = `Σ nanos ÷ 10^3`; saturate at `i64::MAX`; cents floor at 0 (`derive_spend_cents`'s `.max(0)`), micros do NOT (`derive_spend_micros` has no clamp) — PB-16. Postings group
     onto 1.5.5's store rows per `(key, day, lane, provider)`; the legacy `/usage` projection is per §10.
  4. *Immutability*: priced once at settlement with the rate-card version captured at hold from the
     `Policy` epoch current at Admit; a card change (a new `Policy`) applies to holds opened after it and
     never to history; postings already made are immutable INTERNALLY — but the legacy `/usage` projection derives at READ TIME from the CURRENT card exactly as 1.5.5 does (retroactive repricing is 1.5.5 behaviour and is reproduced byte for byte; the immutable posting is on the 1.6.0 endpoints only) — parity clause.
  5. *Tier* (**new in 1.6.0**; 1.5.5 has no service-tier multiplier — its per-tier token classes are
     meter classes here, and an upstream-reported per-response tier prices through the extras table):
     `tier_bp` is a **bucket-level** multiplier from the bucket's config (default 10,000 = 1.0×) applied
     **once over the posting's summed pre-tier nano-units** (a single divide, never a sum of per-line
     floors); `priced_amount = pre_tier_amount × tier_bp
     ÷ 10^4` truncated once; the posting stores `tier_bp`, `pre_tier_amount` and `priced_amount`; the
     recompute (§4.2) applies the same rule.
  The oracle compares quantities byte-identical, amounts as "1.5.5 re-priced at the pinned migration
  card == Σ stored nano-units" (fee and usage separately; an extras cell), plus a mid-window rate edit
  asserting the expected divergence. The tiered-bucket cell has no 1.5.5 reference: its expected amounts
  are the verifier's hand computation only (§8.1).
- The priced **lane** is cross-checked three ways (§2.2) through the lane-alias map; mismatch → the
  cheaper entry, `MeterDisputed`; above `lane_mismatch_alarm` per window per (plane, lane) → alarm, and `draining` on 1.6.0-native planes only (1.5.5's only drain triggers are SIGINT, SIGTERM and `POST /admin/restart` — a node never drains itself on the reference plane). The hold is opened at Σ per-class estimates × the max unit price over the verified set ×
  permitted op classes plus fee, always — INTERNAL only: the hold is accounting and never gates admission (PB-22), so
  its conservatism is invisible to a 1.5.5 user and there is no §8.1 exception. A hook permutation may not change the price beyond `max_priced_delta`.
  **Unpriced**: `allow_unpriced` default **false** (§4.7); a class in the Migration-sealed `unpriced_classes` list prices at 0, `estimated`, `Unpriced` on the disputes
  report — for meter classes outside the card's declared set only; a card present at boot is complete
  over its own set or boot fails (§2.2 step 4); `false` → `Refused(Admit, Unpriced)`.

### 4.6 Fleet admission — bucket chains, branch floats (per-node slices of a bucket window, drawn from the store and fenced by epoch), fencing, propagation

- **Bucket chain and cap dimensions (1.5.5's enforcement topology, kept)**: a principal's chain is key →
  group → parent group → … (from `Policy`, plus **template instances** — 1.5.5's per-subject `user:<sub>`
  leaf group minted by the token verb, see §4.7); each bucket declares caps per dimension `{ nano-units
  (budget), requests, tokens (total) }` — 1.5.5's three — plus the 1.6.0 additions `tokens_in`,
  `tokens_out`, per window (`minute | hour | day | month |
  total`), each optionally **scoped** to a POOL NAME (1.5.5's `pool:` — `applies_to_pool` is equality against the effective pool name, the one predicate every walk uses; lane membership is never consulted, so a by-model request or a pool sharing a member lane never triggers another pool's bucket — governance :112-113), an instantaneous `concurrent` cap (never
  scoped), an `enabled` flag (**frozen** = the bucket and every descendant refuse `GroupFrozen`, history
  kept), and an optional `on_exhaust: downgrade → downgrade_to` on a scoped nano-units cap (§2.2 step
  4). Admit draws **all-or-nothing** across every applicable pre-drawn `(bucket, dimension, scope)` in
  the chain (a `peers:` deployment; on every 1.5.5-shaped deployment, shared store included, the admission cells are NODE-LOCAL, hydrated once at boot and never re-read — PB-59) — one slice per triple, token draws from the per-class estimates (§2.2 step 4); scoped
  buckets whose scope intersects the verified set all draw, unselected scopes released at Route;
  uncapped buckets are attribution buckets — and takes one `concurrent` lease per capped-`concurrent` GROUP (PB-22)
  bucket (a `Lease` record carrying the lease epoch; released on the exit path of every end, or by
  recovery together with the settle; **the store counts only leases whose epoch is current**, so a dead
  incarnation's leases never linger); any refusal releases everything drawn. The §4.2 identity holds per `(bucket, dimension, scope)`. `Refused(Admit, OverBudget { bucket, dimension, scope })` names
  the bucket, dimension and scope (1.5.5's 429 vocabulary; an oracle cell per cap kind, per window kind
  incl. `total`, per scope, per chain depth, plus frozen-group and downgrade cells).
- `reserve(bucket, dimension, amount, node, epoch) → Slice { window_start, valid_until, epoch }`, atomic
  at the store, which computes the window and deducts carried overdraft; postings carry `window_start`;
  near exhaustion the slice shrinks to the exact remainder. Draws and releases are `Slice` entries. A
  hold spanning a window boundary settles into the window it was opened in; a top-up drawn after the slice rolled is journaled as a cross-window transfer `Slice` line `{ window_from, window_to }` so each window's sealed `Checkpoint` totals close (the per-window identity carries `± transfers`).
- **Fencing by kind**: live decisions require `epoch == current`; `append_batch` accepts `epoch ≤
  current` for that node, deduped, `replayed: true`. A node that has not heartbeated within `lease_ttl −
  safety_margin` stops admitting (fleet rule). Outside outage mode (§2.3), at `valid_until` the node releases `slice − Σ settled − Σ
  open holds` and re-reserves; stale-slice holds are `Refused(Admit, StaleSlice)`. The epoch floor is
  persisted in every WAL header and at the anchor; after `StoreRestore` the node refuses to serve until
  `reseal_epoch_floor`.
- Lease expiry: the store waits `release_deadline` = `lease_ttl + 2 × max_unit_duration + skew_max` (1,235 s — so a unit admitted at the last admissible instant of any outage branch, `stale_serve_max` = 630 s, and running the full `max_unit_duration` settles before any slice is released; cell: unit admitted at `stale_serve_max − 1 s` running 600 s, then a second node draws), releases `slice − Σ
  settlements observed`, drops the node's concurrent leases and session-directory entries; replay lands
  as correcting postings; never-replayed spend is `UnreconciledSpend` until `resolve_slice`. **Grace
  slice**: when the store is unreachable at exhaustion, at most `grace_slices_per_window` journaled grace
  draws are admitted locally before fail-closed — a `peers:` deployment only; a peerless node serves through (PB-14).
- **Propagation**: policy epoch on every `Policy`/`revoke` entry; node Tick reads the tail; staleness
  beyond `policy_staleness_max` → stop admitting (fleet rule); Admit compares epochs.
- `FLEET_SAFE` proven by verdict hash for 1.6.0 native-ABI stores only; the four shipped 1.5.5 stores declare nothing and load exactly as at the tag (never a preflight refusal); a second lease is refused only on a `peers:` deployment; N-node conformance includes ±60 s
  injected skew. **Legacy dual-write**: `legacy_cells_write` for one release with the cell "the 1.5.5
  binary reads balances written by 1.6.0"; the boot check refuses slices if legacy cells show an
  unleased write in the current window.

### 4.7 Corrections, disputes, dual control, config, defaults

**Kernel verbs** (executed by `busbar-unit-verbs`, which holds `AdminToken` and builds `SecretOnce`; the
admin plane is the codec only) are a closed table **derived mechanically from 1.5.5's `openapi.json`
at the tag — 66 operations over 49 paths (34 `read-only`, 32 `full` — `POST /config/validate` and `POST /plugins/inspect` are read-only; `required_scope(method, path)` pinned, PB-62) — pinned by git object hash — PLUS the named non-admin 1.5.5 surfaces, each pinned by its handler: `POST /auth/token` (the self-serve exchange; exempt from dual control in both postures, Appendix A) and `GET /auth/token` (the browser exchange: unauthenticated exact-path bypass, `200 text/html` or `302` to the IdP, `?logout` / `?code` / `?method` / `?refresh` dispatch — PB-33), `GET /v1/models` and `/v1beta/models` (governance-scoped listings), `/stats`, `/healthz` (unconditional auth bypass on BOTH listeners), `/metrics` (present only when `export.prometheus` is configured; data-plane key auth) and `/metrics/hooks` (present only when `metrics::enabled()`) — PB-43 — with their own §8.1 effects rows; admin mutations are rate-limited exactly as `admin/rate.rs` (PB-32)**, plus
the 1.6.0 additions: `verify`, `plane_facts`, `plane_record_write`, `set_operator_key`, `set_escrow`,
`chain_break`, `store_restore`, `reseal_epoch_floor`, `set_dual_control`, `set_overdraft_ceiling`,
`set_dispute_max_age`, `commit_upgrade`, `resolve_dispute`, `resolve_slice`, `adjust`, `export_keyset`,
`approve` (the maker-checker approval under `required`: its payload hash must equal the pending mutation's and its approver must differ from the maker) (17 verbs; keyset import is the off-node CLI, not a verb).

**HTTP binding of the 17.** Each of the 17 binds as `<kebab-case-verb>` under the admin prefix: POST for
every mutating verb, GET for the two read-only verbs (`verify`, `plane_facts`). Bindings: `GET verify` ·
`GET plane-facts` · `POST plane-record-write` · `POST set-operator-key` · `POST set-escrow` ·
`POST chain-break` · `POST store-restore` · `POST reseal-epoch-floor` · `POST set-dual-control` ·
`POST set-overdraft-ceiling` · `POST set-dispute-max-age` · `POST commit-upgrade` ·
`POST resolve-dispute` · `POST resolve-slice` · `POST adjust` · `POST export-keyset` · `POST approve`.

The
15 operations the dev tree added to the admin API since the tag are separate new surface with their own
effects cells. `plugins/reload|rollback` are a registry
generation swap sealed by `Load`/`Policy` entries and applied at a unit boundary; the store/governance instance is REUSED across the swap and 1.5.5's reload/rollback mechanics hold (PB-63). **Template
instances**: the 1.5.5 SELF-SERVE exchange verb (`POST /auth/token`, not the admin key mint — whose caller-named `parent` is checked for EXISTENCE only, exactly as 1.5.5's `plan_mint_group` does — parity clause; no containment rule) mints a per-subject leaf bucket taking `resolve_child_default(groups, parent)` — the nearest-ancestor `child_default`, empty when none (1.5.5 has no `user:*` template; the template is a 1.6.0 alias for that rule) — whose `parent` is the role-binding group the exchanging identity maps to in `Policy` (1.5.5's `role_bindings.<module>.<role>.group` — never caller-named, exactly as 1.5.5) from the `user:*` template (caps
inherited), bounded by `max_auto_provisioned_groups`, journaled `Policy { template_instance }`; template
instantiation is **exempt from dual control** (the template itself is a listed key).

**Dual-control posture** is sealed at `Bootstrap`; **default is `single` on upgrade from 1.5.5 AND on a fresh install** (`Bootstrap` tells them apart by the presence of legacy cells; `required` is only ever chosen by `set_dual_control`). Under
`single` every verb applies immediately, journaled, alarmed, on the ledger endpoint (PB-16) (every listed-key delta in the
window is a ledger-endpoint line (PB-16)) — 1.5.5's operating posture. `set_dual_control(required)` needs ≥ 2 admin
principals (`Refused(Approve, InsufficientApprovers)`); `required → single` needs dual control. Under
`required`, maker-checker applies to every mutating verb except `approve` itself (the checker step — its only controls are the payload-hash equality and the `SelfApproval` refusal); the pending response is a named exception.

**Irreducible set, required in both postures**: `chain_break`, `store_restore`, `commit_upgrade`,
`set_dual_control`, `reseal_epoch_floor`, `set_operator_key` (once set), `set_escrow`, `export_keyset`,
changes to the **binary-digest set** (no verb: it changes only through an operator-signed config reload; `plugins.trust.publishers` stays an ordinary 1.5.5 config key applied on reload — CFG-183 / BOOT-134, PB-11) (the 1.5.5 `plugins/reload` and
`rollback` verbs themselves are ordinary mutating verbs — immediate under `single`; the digest set is
initialised at `Bootstrap` with the booting binary's own digest **when an operator key is present, and
is `any` under `operator: unset`** — journaled, alarmed, on the ledger endpoint (PB-16), closed by the first
`set_operator_key`; boot cell), **and `adjust`/`resolve_dispute` above `adjust_threshold`**. Control: an **operator
key whose private half is never on a serving node**. **Ceremony on upgrade**: `busbar operator keygen`
(off-node) → `operator.pub` beside `config.yaml`; **absent at `Bootstrap` → sealed `operator: unset`**,
every irreducible verb refused except `set_operator_key` and `export_keyset` (so the keyset can be backed up before the ceremony — under `unset` it takes a MANDATORY recipient public key, seals to it, and the `Access` entry records the recipient fingerprint; plaintext export is never a path; residual risk in Appendix A)
, which under `unset` are admitted with the admin
credential, journaled, alarmed and shown on the ledger endpoint (PB-16) (so a 1.5.5 config boots unchanged and the fleet
can always be brought under the key; consequence: until the ceremony EVERY irreducible verb other than `set_operator_key` and `export_keyset` is refused — `commit_upgrade`, `set_dual_control`, `set_escrow`, signer/digest changes, and `adjust`/`resolve_dispute` above `adjust_threshold` (floor 10^9 nano-units), so larger disputes stay open and alarmed; disaster recovery is unaffected because `chain_break`, `store_restore` and `reseal_epoch_floor` also exist as off-node CLI on a stopped node — stated here as the cost of `unset`). `busbar policy sign <config>` (off-node) emits a detached
signature read beside `config.yaml`; verbs carry the signature as an argument. Rotation is a `Policy`
entry signed by the retiring key; loss is covered by an M-of-N escrow — **a required argument of
`set_operator_key`** (and of `Bootstrap` when the key is present at first boot), changed only by
`set_escrow` in the irreducible set (break-glass journaled); without escrow the fleet can never
`commit_upgrade` again, and the document says so.

**Config is not a side door**: the dual-controlled key list is a closed constant; the boot cell asserts
coverage. On boot/reload the resolved policy is diffed against the last sealed `Policy`: under `single`,
deltas apply and the diff is sealed; under `required`, a listed-key delta is refused unless a matching `approve { key, payload_hash }`
entry (the maker-checker verb, journaled) carries a payload hash equal to the new value AND an approver fingerprint different from the maker's (at a COLD BOOT under `required` an unapproved listed-key delta in the file is journaled and alarmed, the node SERVES on the last sealed `Policy`, and the ledger endpoint (PB-16) names the rejected delta — the fail-safe choice, and the expectation the "change a fee and restart" cell asserts; for a config-file delta the maker is the admin credential that issued the reload, or the `Bootstrap`-sealed admin at boot) (`Refused(Approve, SelfApproval)`; both sealed in the `Policy` entry; cell); irreducible-set deltas need the operator
signature in both postures. A reload that would violate an operator-pinned `max_unposted_accrual`
(§4.7 table) is refused.

**Defaults (pinned; sealed in every `Policy`; all dual-controlled)**:

| Key | Default | Rationale / constraint |
|---|---|---|
| `K` | 4 | units in flight past decode per session |
| `max_nest_depth` | 2 | tool → tool is enough; deeper is a config decision |
| `max_priced_delta` | 0 | hooks never change price (1.5.5 ranking policies sealed `unbounded` at `Migration`) |
| `may_change_destination` | false | hooks present in a 1.5.5 config sealed `true` at `Migration` |
| `checkpoint_entries` / `checkpoint_interval` | 10,000 / 60 s | whichever first; at the headline rate ≈ 24 checkpoints/s — a §10 measured row |
| `anchor_failures_alarm` | 3 | consecutive |
| `challenge_max_rounds` / `challenge_max_bytes` | 5 / 16 KiB | Handshake units |
| `variance_tolerance` | 1 % | per class family; a card may tighten; applies to `PlaneCount` / `Count × TransportFacts` versus their kernel companion |
| `locator_floor_ratio` | 4 | one-sided sanity bound for `Locator` classes: a located quantity below kernel floor ÷ this ratio posts the LOWER (the located figure) with `MeterDisputed` — the dispute and its alarm are the control against an under-reporting plane, consistent with every other row; the floor is evidence, never a charge; a located quantity ABOVE floor × this ratio posts the located figure with `MeterDisputed` (flag-only upper bound — the wrong-locator meta-test is red in both directions) |
| `lane_mismatch_alarm` | 10 per window per (plane, lane) | then `draining` (1.6.0-native planes only) |
| `max_auto_provisioned_groups` | 0 = unlimited (1.5.5's literal default) | template instances; unbounded, dual-control-exempt minting, possibly of uncapped leaves — stated as such |
| `tier_bp` (per bucket) | 10,000 | 1.0×; ≤ 100,000 (boot refusal above); differing values within one chain are a boot refusal (`TierMismatch`, like currency); a `tier_bp` delta is a ledger-endpoint line (PB-16); Appendix A |
| `keyset_ref` | unset | when set (a secret-plugin ref sealed to the operator key), a node resolves the deployment keyset from the secret plugin at boot instead of `data_dir`, so an explicit-store deployment on ephemeral volumes needs no per-restart ceremony; unset → the keyset lives in `data_dir` and a fresh volume needs `busbar keyset import` — only when `data_dir` is configured; a 1.5.5-shaped deployment keeps its keyset in the store and needs nothing; on a `data_dir` deployment with `keyset_ref` unset and no `Access { KeysetExported }` entry the node boots with a WARNING and a ledger-endpoint line (PB-16) naming the single point of loss; a deployment without `data_dir` (every 1.5.5 config) gets the ledger-endpoint line only, no boot warning (PB-41) |
| `data_dir` (OPTIONAL — 1.5.5 needs no data dir, so neither does 1.6.0: without one the journal is memory-buffered and shipped to the configured store synchronously, durability = the store durability, exactly the 1.5.5 rule, and the deployment keyset is sealed in the STORE at `Bootstrap`; with one, the group-commit WAL and local keyset apply) | UNSET (PB-13: no probe, no files); when written, the probe order `BUSBAR_DATA_DIR` / `--data-dir`, else the value as given, sealed in `Policy` on first boot and honoured thereafter; the refusal names `BUSBAR_DATA_DIR` (read-only-mount boot cell) (1.5.5 has no data-dir key) | WAL + `secret-local` keyset; must be writable, else boot refuses `DataDirNotWritable { path }` |
| `grace_slices_per_window` | 0 | fail closed by default |
| `tick_interval` | 1 s | ≤ 1 s: bounds unposted accrual; checkpoints only on change |
| `interrupt_deadline` | 100 ms | time-to-silence |
| `dispute_max_age` | 7 d | overdue alarms |
| `outage_grace` | 60 s | stale-policy exposure during a fleet outage |
| `drain_quorum` | ⌈N/2⌉, N = the configured `peers:` list length; the test is `N ≥ 2 ∧ stale + draining ≥ max(1, drain_quorum)` | fleet coordination; N ∈ {0, 1} (`peers:` is a 1.6.0 additive key, so a 1.5.5 config has N = 0) → no fleet: the node SERVES THROUGH any store outage exactly as 1.5.5's write-behind metering did and never drains for staleness (PB-14) |
| `policy_staleness_max` | 30 s | revocation propagation bound |
| `lease_ttl` / `safety_margin` / `skew_max` | 30 s / 6 s / 5 s | `lease_ttl > safety_margin + skew_max`; `safety_margin ≥ skew_max + tick_interval` |
| `max_unit_duration` | 600 s | stall detection; replay TTL floor |
| `turn_max_duration` | 120 s | duplex turn bound |
| `max_response` | applies to classes whose `METER_CLASSES.direction` is `Response`; the token chain below is the TOKEN-family special case — every other response class is sized from its own `default_max_response` in its `METER_CLASSES` entry (pinned by the plane, overridable by the card, like the divisor), so a bytes or seconds plane gets a real hold, not 4,096 units (the plane's declaration; the card never re-families; `Input`, `CacheRead` and `CacheWrite` use the exact ingress-derived estimate): the lane's `default_max_tokens` (1.5.5's key), else `limits.default_max_tokens` (1.5.5's key, default 4,096 — only when explicitly present, so a 16,384 config holds 16,384), else the 1.6.0 additive `max_output`, else 4,096 (the serde default of that key in 1.5.5) (never `context_max`, which is the window, not an output bound; 1.5.5 used the value as the upstream output bound, not an estimator — that injection is reproduced by PB-85 (cross-protocol into a lane whose dialect `requires_max_tokens()`, only when the IR carries none, never a clamp of a client value); the hold is accounting and the refusal set is 1.5.5 — PB-22) | hold sizing; a client-located value is clamped to it |
| `max_hold` (derived) | `max_fanout_recipients` × ⌈(Σ_{direction = Response} `max_response_c` (as resolved) × max price_c + max over the classes that partition the same bytes among {direction ∈ Input, CacheRead, CacheWrite} of (`request_body_max_bytes` ÷ divisor_c) × max price_c + fee + `session_idle_max` × max `session_seconds` price + `max_provider_push` × max price_c — the `Kernel`-direction classes appear ONLY as these explicit terms, never inside the partition max) × max `tier_bp` over configured buckets ÷ 10^4⌉ + one accrual step, per unit | the largest hold any unit can open — the tier is in it |
| `max_provider_push` | 1,000 quantity units per class | unsolicited provider hold |
| decline rate `R` / node-global | 100 /s per source; 10,000 /s | aggregation thresholds |
| overdraft ceiling | 10 % of the refusing `(bucket, dimension, scope)` window cap; UNBOUNDED (flag-only) on every Migration-sealed bucket, PB-58 | every capped bucket in the chain |
| `max_fanout_recipients` | 10,000 | `Refused(Approve, FanoutTooLarge)` when `sessions_for` resolves more |
| `in_flight_reserve` | 10 % of `in_flight_cap` when a claimed transport declares `SESSION = true`, else 0 — so a 1.5.5 config sheds at exactly `max_inbound_concurrent` (8,192), PB-44 | held for provider frames of already-open sessions; drawn only against session Unit 0 arrivals |
| `on_empty` (per restrict-capable hook) | `reject` (the 1.5.5 default, PB-1; migrated hooks sealed at `Migration`) | `weighted | reject | first` |
| `in_flight_cap` (`Refused(Arrival, InFlightCap)` for client units, `Refused(Decode, InFlightCap)` for the rest) | read from 1.5.5's `limits.max_inbound_concurrent` (default 8,192; 0 = unbounded as there — then the arrival gate is open, the crash-exposure formula substitutes the node's measured peak in-flight count (published), and an operator-pinned `max_unposted_accrual` requires a finite `in_flight_cap` at boot, `Refused` otherwise) | `Refused(Arrival, InFlightCap)` above it; per-lane `max_concurrent` (1.5.5 `ModelCfg`) is the egress unit's per-destination pool ceiling — fail, never wait — an at-capacity lane is skipped within the pick (PB-2) |
| `max_unposted_accrual` (per node) | **the ONE formula, from enforced quantities**: `in_flight_cap × (max_hold + max overdraft ceiling over capped buckets)` — accrual since the last Tick checkpoint can never exceed a unit's hold plus its journaled top-ups plus the ceiling at which it is aborted; published on the ledger endpoint (PB-16); alarmed above `unposted_alarm`; measured at M2 by the kill-mid-stream cell | asserted at boot/reload only when operator-pinned |
| `currency` | `USD` — the label 1.5.5 emits on the ledger endpoint (PB-16) (`USAGE_CURRENCY`), still abstract minor units | one per bucket; the legacy `/usage` line is byte-identical |
| `session_idle_max` / `peer_table_ttl` | 300 s / `stale_serve_max + tick_interval` (631 s) | session idle close; peer-state aging outlives the quorum branch |
| `stale_serve_max` | `lease_ttl + max_unit_duration` (630 s) | quorum-branch serving bound, before the store's release |
| `slice_ttl` / WAL segment size / `wal_free_min` | 60 s / 64 MiB / 128 MiB | slice `valid_until`; incremental preallocation; discard-posture low-water |
| `MAX_SESSION_UPSTREAMS` | 8 | per session, inside the session budget |
| `spill_budget` | `max_inbound_concurrent` × `request_body_max_bytes` per node; `max_inbound_concurrent: 0` ⇒ unbounded (1.5.5 buffered exactly that much, so no request 1.5.5 accepted is ever refused for spill — parity clause, PB-18) | large-body spooling before `Open`; outside the headline RSS row |
| `per_request_fee` | 0 cents (1.5.5's deploy-level key, independent of the rate card, clamped as there) | posts even with no card |
| `wal_capacity` / `unposted_alarm` | 4 GiB / 1 % of the smallest capped window budget, floor 10^9 nano-units | alarm at 80 %; `unposted_alarm` compares the MEASURED node Σ(accrued − checkpointed), never the formula bound |
| `adjust_threshold` | 1 % of the bucket's window budget, floor 10^9 nano-units (the floor is the whole threshold on an uncapped attribution bucket) | above → operator signature |
| `allow_unpriced` | **false** → `Refused(Admit, Unpriced)`; WITH A RATE CARD PRESENT (1.5.5 `pricing_enabled()`), a client-located NAME resolves to one of three things — a POOL (a candidate-set name, expanded by the trust unit to its member lanes at their own card entries), a by-lane name, or a card lane — and only a name that is NONE of the three for a KEYED principal is `Refused(Verify, UnknownLane)` (1.5.5's guard leg for leg; cell: a keyed request naming a pool with a card present serves and prices at the selected member's entry) rendered byte-identical to 1.5.5's 400, while an anonymous (unkeyed) unit with an unknown lane is served and attributed at 0 exactly as 1.5.5's four-way guard does; with NO card a keyed unknown lane is served at 0 as well (oracle cells: keyed × card × unknown lane; keyed × no card × unknown lane) | 1.5.5 is fail-closed on unknown lanes (its `model_unpriced` rule; it has no meter-class concept); at `Migration` the meter classes 1.5.5 never priced (everything outside its four token classes and the fee) are sealed into an explicit `unpriced_classes` list — journaled, on the ledger endpoint (PB-16), residual risk — so migrated planes keep serving |
| `on_failure` (hooks at gate seats) | closed for hooks added in 1.6.0; the resolved 1.5.5 `on_error` chain of each MIGRATED hook (default `nothing` = the failing gate does not participate; fallback hooks; terminal `weighted | reject | first`) is sealed at `Migration` — cell: a migrated gate timing out under `nothing` still serves | |
| reconciliation `T` | 24 h | |

Evidence reads (`read_*`) are pinned at 0 and never refused for budget. Encode failure after posting →
kernel-default body + reversal, always. Every `recovered`, `estimated`, `Unpriced`, `MeterDisputed`,
`Overdraft`, `stale_policy`, `late_accrual` and `unposted` posting is on the open-disputes/exceptions
report until a verdict; overdue beyond `dispute_max_age` alarms; the `Reconciliation` entry carries
the counts.

### 4.8 Policy, boot, bootstrap, versions, clock

- Every boot/reload seals `Policy { binary_digest, resolved policy incl. the defaults table, hash,
  policy_epoch, dual_control, operator_pubkey | unset, escrow }`; boot refusals — ONE list, mirrored verbatim in §10, in two parts. (a) The 228 refusals and warnings of 1.5.5, byte-identical (inventory C2) incl. rate-card completeness, the admin-listener mTLS guard and the serde unknown-key message with its `expected one of` list unchanged (every 1.6.0-additive key lives under the single `fleet:` block, split off before the 1.5.5-shaped parse — PB-40). (b) Refusals that can ONLY fire on 1.6.0-additive keys and therefore never on a 1.5.5 config: overlapping claims across planes; mixed currencies; `TierMismatch`; the operator-pinned accrual bound; a secret ref in a plane CONFIG_SCHEMA; `MissingDefaultLaneRow`; `KeysetMissing` and `DataDirNotWritable` (only with `data_dir` configured); `PluginAbiTooOld` (only for a plugin newer than the native ABI); a manifest OUTSIDE its kind's window (the store window is [2,4], PB-11) is refused with 1.5.5's literal and the current printed range (PB-11).
  The secret-ref refusal also fires on a value matching the canary — only for values reached through a 1.6.0-additive key or a plane `CONFIG_SCHEMA`; 1.5.5 scans no value content (PB-17).
- First boot synthesizes a `Bootstrap` unit sealing the admin credential's fingerprint, the posture, the
  operator public key (or `unset`) and the escrow; single-use (`AlreadyBootstrapped`).
- Every entry carries schema and hash-algo versions; a node writes at the committed version (`Migration` seals the committed version as the 1.6.0 initial schema, so an upgraded fleet never needs `commit_upgrade` until 1.6.x → 1.6.y) and reads at
  its own; a node whose maximum observed version exceeds its own refuses to serve; older nodes refuse
  after `commit_upgrade`. 1.5.5 → 1.6.0 on a 1.5.5-shaped deployment is a ROLLING start (PB-13: the first node to boot mints the deployment keyset, seals `Bootstrap` in the store and runs `Migration`; every other node reads it); the stop-the-world sequence (stop every node; start node A; `export_keyset` from A; `busbar keyset import` on every other stopped node; start them) applies only when `data_dir` is written; `Migration` as in §4.2; legacy dual-write for
  one release; rollback uses the 1.5.5 binary with its ABI-2 store on the dual-written schema. Oracle
  cells: rollback; two 1.6.x binaries; restore from backup.
- Wall for timestamps; monotonic for timeouts and hold expiry; both on every entry; clock-backwards test.

### 4.9 Audit record — fixed, required, identical for every plane

who (pseudonymous principal or arrival subject) · what (unit key, `op_class`, verified destination,
parent, pre/post hook head) · when · outcome (`UnitEnd`, step, `HookFailed`, emission under/overrun,
`stale_policy`) · amount (usage lines with sources, pre-tier and priced nano-units, `tier_bp`,
`fee_count`, currency, rate-card version, bucket-chain ref) · controls (hold/settle/slice/lease refs,
epochs, hooks applied with priced delta, replay, children) · integrity (prev hash). A plane contributes an op-class id and a finish class;
two ids. Content is never in the chain; `content_facts` (incl. the correlation label) flow only to
export plugins; every hook/export content access is an `Access` entry.

---

## 5. Transports (in-tree)

| Key | Frames | Composes over / handoff | `SESSION` / `SESSION_BOUND` / Unit 0 | Upgrades / handshake | Notes |
|---|---|---|---|---|---|
| `tcp` | byte stream | — | true / false / first bytes | `tls` | base |
| `tcp-line` | line-delimited duplex | `tcp` | true / false / first line | `tls`; no `HANDSHAKE_TRIGGER` — the plane opens its handshake units | non-HTTP litmus |
| `tls` | framed over TLS | `tcp` | inherits / true | — | keys via the transport-key unit |
| `dtls` | datagrams over DTLS | `udp` | true / true / first handshake | — | |
| `http` | request; response frames | `tcp`/`tls` | false / n/a / none | — | no session; carries the per-frame `StatusClass` at `FirstFrame` (the fee's kernel-derived leg); the egress client is 1.5.5's verbatim — `redirect: Policy::none()`, `connect_timeout` 10 s, `tcp_keepalive` 60 s, `tcp_nodelay`, the HTTP/2 keep-alive and adaptive-window settings, `pool_max_idle_per_host` / `pool_idle_timeout`, `advanced.upstream_http1_only` / `upstream_h2_prior_knowledge` (PB-56); active health probers per `health.mode` run as a kernel Tick (PB-55) |
| `sse` | request + N response frames | `http` | false / n/a / none | — | inherits `http`'s per-frame `StatusClass` at `FirstFrame` (composed transports inherit the lower layer's status leg; `ws` frames after the upgrade carry none, so the plane's `finish` is the sole source there — stated) |
| `ws` | duplex message frames | `http` over `tls` | true / true / the upgrade | — | |
| `grpc` | unary + multiplexed streams | `http` | true (streams) / true / first message | — | carries the per-frame `StatusClass` at `Terminal` (the `grpc-status` trailer) |
| `stdio` | duplex framed | — | true / true / first message | — | |
| `udp` | datagrams | — | true / false / first datagram | — | flow = open unit; decode failure is `Discard` |
| `webrtc` | SDP over `http` (one-shot) with **handoff** to RTP media + SCTP data over `dtls`/`udp`, bound by the DTLS fingerprint in `TransportFacts`; ICE endpoints allow-listed; `DECODES_PAYLOAD = true` for RTP (units from timestamp deltas ÷ clock rate) | `http` → `dtls` | true / true after handoff / the SDP offer | — | a sans-I/O WebRTC crate (str0m-class) under `deny` |
| `twilio-media` | JSON envelope carrying base64 μ-law (`DECODES_PAYLOAD = true`) | `ws` | true / true / the upgrade; `start` is the first client unit | — | |
| `peer` | closed peer envelope, `auth-lease` authenticated | `tls` | true / true | — | never a claim target |

Transport battery (identical for all): byte-exact round-trip inbound and outbound; half-close; cancel
mid-frame; no session without a Completed Unit 0 (except kernel-internal `peer`); every `TransportError` → its `UnitEnd`; bidirectional
backpressure; two-level composition with a bottom-layer credential; handoff with fingerprint mismatch
refused; in-band upgrade (Handshake unit) with cleared facts; challenge-response handshake ≤ `challenge_max_rounds`;
multiplexed streams without cross-talk; K writers; overlap cases; emission clock honoured; honest frame
meta (inflating and deflating fixtures red); forged-source datagram → `Discard`, zero postings, session
intact; the echo plane unchanged.

---

## 6. Planes

A plane is CLAIMED only when its config block is present: a 1.5.5 config claims `llm` alone, so no session transport is claimed and `in_flight_reserve` is 0 (PB-44); the three additions cost a 1.5.5 deployment nothing until configured.

| Plane | Dialects (deny-list source for §1.3) | Claims | Units | Meter classes (the classes each plane METERS; kernel-reserved ones are declared by the kernel) | Records | Notes |
|---|---|---|---|---|---|---|
| `llm` | anthropic, openai, responses, gemini, bedrock, cohere | http, sse | request; streamed response | tokens_in, tokens_out, cache_read, cache_write (1.5.5's four, read per PB-86: plane-normalized — cached count subtracted from the wire prompt total on openai/responses/gemini, gemini `tokens_out` = candidates + thoughts) PLUS 1.5.5's non-chat classes sealed at `Migration` (`Billing::Flat` moderation, the per-op meters for embeddings / image / transcription / speech / rerank — PB-87, never `Refused(Admit, Unpriced)`; + extras) — `requests`, `fee`, `count`, `session_seconds` are KERNEL-RESERVED keys, DECLARED by the kernel itself as meter classes with direction `Kernel` (they enter neither the ingress partition nor `max_response`; each is sized by its own rule: `fee` 1, `requests` 1, `count` the kernel Count, `session_seconds` `tick_interval` or the §2.2 catch-up) — plus the AGGREGATE class `tokens` (family token, direction `Kernel`, never priced by a card; `Class(tokens)` draws Σ over its four member estimates and settles to Σ of their actuals) so `Class(...)` caps over them have a declaration site; the registry refuses them from any plane | — | 6 dialects × cross-dialect; reference = 1.5.5; an idempotency location is CLAIM CONFIG, absent in a migrated 1.5.5 config (1.5.5's proxy path reads no client idempotency key, so the 1.5.5 shape stays byte-identical); a config that opts in gets the keyed-retry refusal|
| `mcp` | mcp (JSON-RPC) | http, sse, stdio | JSON-RPC request; sampling as provider `OneShot`; outbound sessions | tool_calls, bytes | tool catalogue, approvals, settings | |
| `a2a` | a2a | http, grpc | task ops; push events as provider units | bytes | tasks, push configs, pins | |
| `admin` | busbar admin v1 | http | one kernel verb = one unit (codec only; `busbar-unit-verbs` executes) | count | — | mints via `SecretOnce` |
| `voice` | openai-realtime, gemini-live, twilio-media-streams, one-shot transcribe/tts | ws, webrtc, twilio-media, http | a turn; tool calls as provider `OneShot` requests (`Client(AwaitReply)` or `NestedPlane(mcp)`, result as a `SessionUpstream` leg); interrupt fact; pacing fact; one-shot transcribe/TTS | audio_tokens_in/out (`Locator`), text_tokens_in/text_tokens_out (`Locator`), cached_tokens, audio_seconds_in (`TransportUnits` on twilio and webrtc; cross-checked by `KernelElapsedMono`; `Locator` on ws), tool_calls | — | OpenAI Realtime ingress/egress; Gemini Live egress; μ-law↔PCM16 in `encode_ingress_frame`; **raw SIP out of scope** (owner decision); only the FIRST decoded IR event per wire frame is acted on; uplink audio is ASSUMED PCM16 for the `audio_seconds_in` estimate; model-emitted text in a duplex turn prices under `text_tokens_out` — an OUTPUT class, never the input one — because §4.5 clause 2 makes the class a money question and emitted text is output, not input; the `webrtc` leg and the one-shot transcribe/TTS wire shape are §9.3 Phase 0.5 work, not Phase 0 |
| `blob` (acid test) | s3-style multipart | http | streaming multipart as an open unit | bytes_in/out, objects (`PlaneCount`, no same-unit companion → `estimated` under the implausibility bound) | — | |
| `msg` (acid test) | line-delimited pub/sub | stdio | one message; fan-out across two nodes (aggregate + `peer`, by locator when oversize) | messages, bytes, recipients | subscriptions | |
| `smtp` (acid test) | smtp, esmtp | tcp-line | one message; SMTP AUTH inbound as a challenge-response Handshake unit; STARTTLS as a Handshake unit inbound and an `Upgrade` leg upstream; AUTH to the MX via `Handshake` decoration | messages, bytes, recipients | — | |

**Governance granularity per plane shape** (stated): request/response planes per request; streaming
planes per unit with per-frame accrual; flow planes (VPN) per flow — destination verified at open,
a flow whose destination changes is a NEW flow: the plane emits `Close` + `Open` on the same frames and the new unit runs all seven steps (plane-side; no per-frame Verify seat exists and none is needed — a
flow re-open costs one unit; measured as the §10 latency row); broker planes per message.

**Adding a transport** = one in-tree transport crate (planes do no I/O, so a new wire protocol is a new transport crate — the expected path); a line in an EXISTING transport or in the kernel is the finding. **Adding a plane** = one crate from `plane-template`. If it needs a kernel or transport line, the kernel
is wrong and that is the finding. **Plane-X litmus**: SMTP · blob · embeddings · image generation · SQL
proxy (SCRAM as a challenge-response Handshake unit) · Kafka/MQTT (cross-node fan-out; SASL handshake;
message-level) · video · SSH/git · webhook fan-out · vector DB · VPN (Noise handshake; flow-level) · DNS.

---

## 7. Other kinds

- **Auth**: `LOCATIONS` (arrival forms) + `verify` (pure, or `IO: true` for LDAP/OIDC with a deadline and
  `Access` entries) returning facts or a `Challenge` inside a Handshake unit; `refresh` on the node Tick
  for key material; `auth-lease` mandatory.
- **Egress-auth scheme**: `decorate` → `Decorate` or `Handshake`.
- **Store**: native ABI 5; ABI 2 loads through the in-tree adapter (parity clause);
  required methods; blocking pool; `FLEET_SAFE` (native ABI only, never a `Load` precondition for a 1.5.5 store)
  proven; boot write-read-back ONLY when `data_dir` or `peers:` is written — a migrated config boots on 1.5.5's read-only hydrate (PB-42); gap detection; measured record rate published. memory and postgres
  (in-tree); sqlite, postgres, mysql, valkey (four external repos).
- **Secret**: `resolve`, `watch` (inert for migrated refs, PB-34), `sign`, `seal/unseal` (SIV-AEAD); `secret-local` mandatory in-tree;
  canary grep.
- **Hook**: four seats mapping 1.5.5's four stages; `Tap` (facts only) and `Gate` (veto / restrict /
  rewrite / permutation); `HookView` declared-key; `HookFacts { permutation, restrict, veto, rewrite, tap }`;
  `on_failure` default closed for 1.6.0-native hooks only; a migrated 1.5.5 hook keeps `on_error` default `nothing` (the failing gate does not participate — §4.7, PB-1); `HookFailed`; `max_priced_delta`; `may_change_destination`.
- **Export**: at-least-once with ack for 1.6.0-native export plugins; the 1.5.5 `export:` sink subsystem (prometheus, request-log-webhook, request-log-file, otlp) stays fire-and-forget at-most-once with its admission gate and `durable: true` refusal (PB-12); `Segment` export for retention; `ANCHOR`; owns sink and retention.
- **Dynamic ABI**: auth/secret/hook/export/store; adapters; mandatory signatures; `Load` entries.

---

## 8. Proof

### 8.1 The shadow oracle
- **Reference plane**: response bytes and ledger quantities byte-identical after named normalization;
  amounts equal to 1.5.5 re-priced at the pinned migration card (usage and fee separately; tiered and
  extras cells). Cells: dialect × dialect × outcome class; every `UnitEnd` × step; failover at attempts 1
  and 2; ≥ 10-line posting; ≥ 3 lanes × ≥ 2 keys; mid-window rate edit (expected divergence); non-zero fee
  + usage; keyed retries; a 1.5.5 config with no rate card; a 1.5.5 config with a rate card missing one
  lane (**boot refused**, byte-identical validation message); an unknown lane at runtime (1.5.5's 400,
  byte-identical); a migrated plane meter class in `unpriced_classes` (served, priced 0, `Unpriced`)
  versus a new class with `allow_unpriced = false` (`Refused(Admit, Unpriced)`); a zero-config 1.5.5 deployment (attribution buckets only, identity
  Σ settlements == Σ accrued); the flat fee on every non-2xx outcome class (`fee_count = 0`) and on a
  2xx stream that dies mid-way (`fee_count = 1`, 1.5.5 refunds on status only); a create and a rotate
  sharing one idempotency header; **every cap kind (`budget`, `requests`, `tokens`, `concurrent`) ×
  every window kind incl. `total` × scoped/unscoped at every chain depth in the migration corpus;
  frozen group; `on_exhaust: downgrade` (served through `downgrade_to`, posting `downgraded`); a
  ranking policy (pick order byte-identical) and a config naming NO policy (the SWRR floor, pick order byte-identical); an admin key mint under any existing parent (byte-identical; existence-only check, as 1.5.5); the admin plane under a non-zero fee (zero fee/requests postings); a chunked ≥ 1 MiB body at a budget boundary; a same-node cross-bucket fan-out recipient (priced once); keyed × no card × unknown lane (served at 0); a `tier_bp` ≠ 10,000 bucket at a budget boundary; a `concurrent` cap on a plane whose units never route upstream; a 64-byte-plus idempotency key (never truncated); one boot cell per 1.5.5 route through `PathPattern`; a declared-length body with a body-reading gate (whole body seen); a session-budget refusal at Unit 0; a chain with mixed `tier_bp` (boot refused); a per-lane `max_requests` budget (exhaustion, failover on exhaustion, refund on body failure, pick order with `budget_remaining`); every lane hard-down (one `requests` slot consumed, `fee_count = 0`); a restrict-to-empty under each `on_empty` terminal — `weighted` per PB-28, `first` takes the gate 503 exactly as `reject` (PB-1), `reject` at `After(Admit)` (slot consumed) and at `Before(Route)` (`Failed(Route, RestrictedEmpty)`, slot consumed); keyset lost with the journal present (off-node import); a scoped `requests` cap on a non-selected pool (unchanged, byte-identical); a provider push through `SessionUpstream` (`fee_count = 0`); AUTH then N messages on one unbound-transport connection; a memory-store node on a disk smaller than `wal_capacity` through two fills (continuous admission); every migration-corpus config carrying a secret ref (boots); self-approval refused under `required`; a `Completed` unit with no usage locator (priced 0 on every 1.5.5 surface; the floor internal only); token-verb
  auto-provisioned leaf bucket**; admission at a budget boundary under concurrency (byte-identical
  cardinality — the hold is accounting, the decision is 1.5.5's); a mid-window rate edit (`/usage`
  reprices at read time exactly as 1.5.5; the immutable posting is on the 1.6.0 endpoints).
- **Effects-spec outcome classes (closed)**: `ok`, `ok_stream`, `unauthenticated`, `out_of_scope`,
  `over_budget { bucket, dimension, scope }`, `malformed`, `upstream_down`, `disconnect_mid_stream`, `timed_out`,
  `plane_panic`, `task_lost`, `stalled`, `revoked_mid_session`, `superseded`, `meter_disputed`,
  `unpriced`, `recovered`, `voided`, `late_accrual`, `unposted`, `encode_failure_reversal`,
  `attempt_abandoned`, `replayed`, `in_flight`, `overdraft`, `stale_slice`, `stale_policy`,
  `session_facts_exhausted`, `restricted_empty`, `post_meter_amendment`, `fan_out_partial`, `handshake`, `discard`.
- **Admin**: cells derived from the tag's HANDLERS (66 operations; `openapi.json` under-specifies the wire — no `security`, no `Idempotency-Key`, `201` vs `200`, the `Error` enum — and is pinned only as the served blob, PB-75) under `single`,
  byte-identical, including body replay across two nodes at t = 500 s (same node: byte-identical replay; a second node MINTS TWICE, as 1.5.5) and t = 700 s (TTL expired: a fresh mint, compared after the minted-secret normalization); the 15 dev-tree
  additions have their own cells; the operator-key ceremony cell ("1.5.5 config, no operator key: boots;
  `commit_upgrade` refused; `set_operator_key` then `commit_upgrade` succeeds"). **Boot**: one cell per
  migration-corpus config regenerated through 1.5.5 at M1; "one fee edited + restart" under both
  postures; overlap refusal.
- **Effects spec**: cardinality and outcome columns derived mechanically from 1.5.5 where they exist;
  amount literals hand-computed by a verifier with no kernel access who re-derives §4.5's clauses 1–4
  against `cost.rs` and clause 5 from this document alone (the tiered cell's only reference); hashed;
  pinned; owner-signed. **No diff-accept — live or
  expired — covers `usage_lines`, `pre_tier_amount`, `priced_amount`, `tier_bp`, `fee_count`, `currency`,
  `rate_card_version`, cardinality, or any settlement flag**; the negative corpus contains a pair per
  field. Named owner-signed exceptions: NONE for any 1.5.5-reachable surface (parity clause); the only exception is the `required`-posture pending response, a posture no 1.5.5 config can be in.
  (the `required` posture is unreachable from a 1.5.5 config.)
"Live accepts" = unexpired entries; capped at 20.
- **Other planes**: passthrough-diff; mock-derived effects; conformance-rig refusal shapes. **Terminated
  transports**: recorded rig with byte-exact control-plane diff; media fixture; live smoke. Cross-plane
  invariant: identical quantities in one meter class bound to one price produce identical postings.
- **Normalizer**: rules are diff-accept entries; two approvers on `effects` diffs; the integrator never
  approves their own; freeze 4 h before cutover.

### 8.2 Closed loop, coverage, reconciliation
- Every cell: all three surfaces show the entry; Σ stored nano-units == window cells == metric;
  quantities == upstream-reported usage; the §4.2 identity per `(bucket, dimension)`; the independent
  recompute matches; one out-of-band store read; the two-sided canary.
- **Derived feature matrix** (`qa/plugin-coverage.json`) at 100 %, nightly, committed report, drift.
- **Meta-tests**: under-reporting plane; wrong-locator plane; expensive-lane plane; op-class-mislabelling
  plane; stateful plane; socket-opening plane; header-echo plane; unrecorded fixture; tampered WAL
  segment; malicious egress-auth scheme; destination-steering hook; hook exceeding `max_priced_delta`;
  frame-inflating and frame-deflating transport; under-counting socket counter; **lying store** (a
  `claim_key` returning fresh twice → the two-sided canary; an over-issuing `reserve` and a forgotten
  settlement → the §4.2 identity at the next `Reconciliation`, detection latency ≤ `T`); **lying
  secret plugin** (a signature that does not verify against the public half sealed in `Policy`);
  **echoing anchor** (returns a head it was never given → `verify` fails on the anchored-head
  comparison); lying-`finish` plane (must be red via the `status_class` second source); lying negotiated frame
  timing (must be red via the variance rule); transport reading its key handle; a plane `loop {}` at
  each call site (`Stalled`); the doc scan over this file.
- Call-site attribution: `cfg(busbar_conformance)` build differing in one file; release binary replayed.

### 8.3 Batteries, gate, mutation — the full register

**Kernel battery** (named cells): every step order · every refusal reason · every `UnitEnd` · `kill -9`
at every durability point, between every adjacent pair of steps, between `claim_key` and the hold,
between legs, and mid-`pwrite` (torn tail truncated) · young hold from a dead incarnation recovered at
boot · EIO and ENOSPC at every sync point · resolved-principal refusal survives `kill -9` · resolved-
principal refusal caused by WAL failure · panic at each of the 18 plane call sites while a hold is open ·
transport stream panic mid-unit · task-abort attempt rejected by the scan; `TaskLost` at runtime shutdown
settles within one tick · plugin call exceeding its deadline → `PluginTimeout` · overlapping claims
refuse boot (every form pair) · double bootstrap · store killed mid-run · store 10× slower than ingest ·
restart with N un-shipped entries · two nodes same key same instant · ±60 s skew · lease expiry with and
without WAL (concurrent leases dropped) · live-node partition · restore from a pre-partition backup;
restore below the backup watermark → `ChainBreak` · store unreachable for 2 × `lease_ttl` (fleet rule;
`drain_quorum`) · grace slice consumed then fail-closed · all-or-nothing chain draw: refusal at the
parent bucket releases the child's slice · `concurrent` cap across two nodes · K parents blocked on
children · parent `TimedOut` with a queued child · unsolicited provider push at the cap · barge-in
racing Meter entry; frames emitted after CAS = 0 within `interrupt_deadline` · emission overrun on
stream (backpressure) and datagram (`unemitted`) · fan-out across two nodes with a refused recipient;
node A killed mid-fan-out; oversize payload by locator · N sources below R; 10×R from one source ·
decline lost within a commit window (measured) · masked credential span; 6 KiB bearer fits the slab ·
Handshake unit STARTTLS clears facts and principal · SCRAM-style challenge-response ≤ `challenge_max_rounds` ·
forged-source datagram → `Discard` · two principals on one unbound session: B's `correlates` to A's
unit posts to B · change a fee and restart under both postures · mid-window rate edit leaves history
byte-identical · overdraft in window N reduces window N+1 by exactly that amount · revoke on A → refused
on B within the bound · idle session with a dry budget closes within one tick · rotate the signing key;
rotate the operator key; `verify` · purge refused while a dispute references the segment; purge then
reconcile · default store disk-full behaviour · anchor sink unreachable N times · rolling restart with
zero mid-turn aborts · kill a node mid-stream against the unposted-accrual budget · `late_accrual`
posts once, flagged · cursor and credential budget exhaustion pre-authentication · refusal of request
*n* on a multiplexed stream leaves *n±1* completing · exhausted budget + overdraft ceiling + saturated `concurrent` cap → `/audit` and `/usage`
still returns · a provider `OneShot` refused at Verify leaves the session open (floor line posted); one refused `OverBudget` at Admit posts the floor line and hard-closes · drop one principal's pseudonym
key: `verify` passes, others resolve · dispute older than `dispute_max_age` alarms · `PlaneRecord` across
restart on every store · the 1.5.5 binary reads legacy cells written by 1.6.0 · `session_put` cleaned on
lease expiry · the operator-key ceremony · 3-node upgrade keyset import · accrual bound violated on reload is refused.

**Unit invariants (solo batteries)**. Ledger: priced once and stored in nano-units (pre-tier and
post-tier); integer sums order-independent; derive after settle returns exactly what was settled;
cents/micros only at read, truncation once, fee after; rollover at the boundary; all-zero tier is a
no-op; tier applied once over the sum; concurrent settles sum; corrections are reversals. Audit chain:
every entry verifies; append-only; read-back byte-equal; a seal is recorded; restart replays to the
anchored head. Admission: all-or-nothing chain draw; hold ≤ slice; top-up journaled; `Exhausted`
continues with `Overdraft`; stale slice refused; last unit exact; concurrent lease released on the exit path for every end.
Breaker: trip/cooldown/fast-fail; half-open probes journaled. Cost/usage: the five clauses; variance
rule; lower-evidence table; independent recompute.

**`cargo xtask gate`** (M1; built, not re-pointed): both feature builds; clippy; fmt; manifest
allow-list; source denylist (pure kinds, transitive); `blocking-ffi-lint`; AST scans (default bodies,
stub facts, `expose()`/`SecretOnce`/`SecretSlot`, interior mutability, lean core (literal comparison) +
doc scan, Teller exits, `Hold` capture/forget/leak, task abort, cancellation checks at awaits, `Bytes`
in the contract, `forbid(unsafe_code)`, feature-invariance, ABI surface); `profile-lock` incl. `panic`;
perf jobs (§10) with match-count floors; oracle replay; batteries; coverage 100 %; LOC ceilings (union,
per file, by call-graph); test-LOC ratio; live-accept cap; migration-corpus currency.

**Mutation gate** (M1): CI job with verdict; per-file floors; equivalent-mutant register (exact line,
argument, why untestable, verifier-signed — never the author — ≤ 3 per file, ≤ 90 days, **a given
mutant line may be registered once ever; re-registration needs an owner signature**); 100 % of
non-equivalent mutants on the seven files; per-file floors across the full crate list of §3.1.

---

## 9. Plan

### 9.1 Phase −1 — Foundation (dated milestones; each go/no-go with a named stop-loss action)
Created here (none exist today): `busbar-contract`, `busbar-caps`, `busbar-kernel`, `busbar-unit-*`
(incl. `verbs`, `breaker`, `wal`), `xtask`, the mutation CI job, `qa/perf-profile.json` (recording the
120k/15 MB provenance — today unsourced), `qa/plugin-coverage.json`, `docs/design/streams/`, the
full-tree `reference/1.6.0-pre-rebuild` bookmark (M1 task), `plane-template`, the echo plane, the JSON
span scanner, the Rust oracle, the effects spec, the kernel-verb derivation artifact, the regenerated
migration corpus, `auth-lease`, `secret-local`,
the in-tree postgres ABI-5 driver, and the ABI-2 adapters so the four external store repos load UNCHANGED (their floor-5 ports are a 1.6.x follow-on, not a 1.6.0 gate).

| Milestone | Date | Green means | Stop-loss action |
|---|---|---|---|
| **M1** contract + caps + kernel skeleton + gate | 2026-09-17 | contract crates with every fixture; `xtask gate` and the mutation job run; templates red; 1.5.5 golden recorded; `panic` pinned; corpus regenerated; the ABI-2 adapters load all four external stores unchanged (PB-11) | oracle or effects spec not green → M1 slips day-for-day and D moves by the same amount, once, owner-signed; an adapter red → M1 slips day-for-day |
| **M2** durability + admission + §10 skeleton | 2026-10-01 | WAL, group commit, fencing, propagation, bucket chains, branch floats green with §4.3 budgets on a one-shot skeleton over `tcp`/`tls`/`http` with the memory store and the in-tree postgres driver; §10 rows measured and constants pinned | if §10 and §4.3 cannot both hold: the §10 numbers do not move; D moves once by 14 days, owner-signed, and Phase 0.5 absorbs the gap |
| **M3** transports + units + K-route | 2026-10-15 | every §5 transport green on its battery incl. the echo plane; session-RSS row measured; K-route shadow-diff = 0 on streaming; all four external stores green through the adapters on the store conformance testkit | `webrtc` red → moves into the voice window after Phase 0.5 (voice date moves; D holds); any other transport red → moves to Phase 0.5 with its planes' claims disabled at boot; an adapter red → carried to M4 as a hard gate |
| **M4** probe (the freeze) | **D = 2026-10-29** | every probe cell green; rps ≥ 1.5.5's measured baseline with durability on; **all four external stores green through the ABI-2 adapters** (nothing ships read-only; floor-5 native ports are a 1.6.x follow-on) | fewer than all probe cells green, or any adapter red → D+14 set once, owner-signed; the release scope is never cut |

**Probe cells** (built at M3/M4 on the finished transports with **template-derived thin plane
slices** — the echo plane plus the minimum codec each cell needs; the full planes are Phase 0
deliverables and are not required for the freeze): reference-plane non-stream + streamed + failover at attempts 1 and 2 · every cap kind
at chain depth 2 · duplex echo with concurrent client/provider units, a Tick, a revocation, an interrupt
· upstream-announced turn boundary · JSON-RPC sampling as a provider `OneShot` inside an open response ·
50 fps open unit with transform and paced egress · nested tool call with a `SessionUpstream` result leg ·
`Client(AwaitReply)` with deadline expiry · K parents blocked on children · unsolicited provider push ·
two-node fan-out (aggregate + remote + by-locator) with node A killed · WebRTC SDP handoff to DTLS-SRTP
with fingerprint binding · Twilio `start` over `ws` · `smtp` over `tcp-line` with a challenge-response
handshake, STARTTLS both sides · `PlaneRecord` round-trip across restart · live-node partition ·
fleet-wide store outage with `drain_quorum` · load at slice exhaustion · ≥ 10-line tiered posting · kill
mid-stream against the unposted-accrual budget · the operator-key ceremony.

### 9.2 Phase 0 — The 48 hours
**Streams** (one card each, disjoint files): **P-*** = plane streams (remaining reference-plane dialects,
`mcp`, `a2a`, `admin`, `blob`, `msg`, `smtp`, voice's second egress dialect, voice's transform);
**K-*** = kernel-unit streams (one per `busbar-unit-*`, incl. K-breaker and K-route — the egress unit's
failover/pool rewrite from the old walk/pipeline as spec); **T-*** = transports; **A-*** = auth plugins;
**E-*** = egress-auth schemes; **G** = gates and scans; **J** = closed-loop battery, effects spec,
coverage matrix; **I** = adapters for dynamic kinds. Merge waves H12/H24/H36/H48; mutation each wave;
diff-accept freeze at H44; cutover in one commit.

### 9.3 Phase 0.5 — 48 hours of performance (§10 absolute numbers are the only done-criterion), then voice
Voice = one plane crate from the template + the bookmarked codec. If it needs a kernel or transport
line, the finding names the rule. Plane 5 is the same one-file job.

---

## 10. Performance and compatibility — hard gates

The public benchmark (`onthebench.ai/gateways/performance`, custom mode, the reference plane's
same-dialect passthrough) is the yardstick. The pre-rebuild figures (**120k rps, 15 MB peak RSS**) are
unsourced in the repo today; M1 records their provenance or re-measures them. **Which number governs**:
the absolute gate below (120k, 15 MB) is the Phase 0.5 exit bar regardless of what M1 finds; M4's
interim bar is 1.5.5's measured baseline; if M1's re-measurement of the pre-rebuild binary lands below
120k, the gate stays 120k. **Reference profile `qa/perf-profile.json`**:
16-vCPU ARM64 class; NVMe with power-loss protection; Linux 6.x; TLS on with pooled, bounded TLS buffers
returned on idle (per-connection bytes measured at M2); 1 KiB / 2 KiB bodies; keep-alive connection
count = the public benchmark's published concurrency for custom mode (recorded in the profile at M1;
the arena formula is a **prediction** at that concurrency, confirmed by measurement at M2); upstream RT
1 ms for the headline row; the memory store for the headline row with a null-sink export plugin acking
segments so retention purges (run duration 60 s; at the gate rate the journal writes ≈ 120k × 2 × ≤ 512 B
≈ 123 MB/s, so `wal_capacity` alone would fill in ≈ 35 s — the row is defined with the export, and boot
warns, ONLY when `data_dir` is written, when `wal_capacity < expected rps × records per unit × record bytes × the retention horizon`); a **shipping row at 30k rps against postgres** at its measured record rate;
changing the profile is dual-controlled. **Arena formula**: peak RSS = fixed + connections ×
per-connection bytes + in-flight × (4 KiB arena + actual cursor/credential/spill bytes) + sessions ×
per-session bytes; every term is a measured row; **the formula must close at 15 MB for the headline row — the M2
finding if it does not**.

| Gate | Number | Instrument |
|---|---|---|
| Throughput, headline row (unkeyed, memory store, durability on) | **≥ 120k rps** | rps job |
| Throughput, keyed units (postgres `claim_key`; 20 % keyed mix) | **≥ 30k rps** at M2 | rps job |
| Store precondition for the shipping row | postgres measured record rate ≥ 2 × 30k units/s | shipping job |
| Shipping lag during the shipping row | ≤ 1 s p99 | shipping job |
| Latency overhead per unit | p50 ≤ 1.5.5 measured + 2 × 0.2 ms (durability) + 0.1 ms (kernel: seven steps, span scan, hashing, in-flight table, slice path — pinned, measured at M2); p99 ≤ 1.5.5 measured + 2 × 0.5 ms + 0.3 ms | latency job |
| Peak RSS, headline row | **≤ 15 MB** | RSS job |
| Per-connection bytes (idle, TLS) | measured at M2; pinned | RSS job |
| Peak RSS, product-realistic row: 10,000 in-flight units at 2 s upstream RT (the row sets `in_flight_cap = 10,000`) | ≤ headline + 10,000 × 6 KiB (arena + actual cursor share) ≈ 75 MB, pinned at M2 from the formula | RSS job |
| Peak RSS, spill-engaged row: `spill_budget` fully engaged by concurrent large bodies | headline RSS + `spill_budget` + measured overhead, with the HOLD-TIME term (spill lives until the egress body is encoded, so occupancy ≈ large-body rate × upstream RT × body size); pinned at M2 | from the formula; pinned at M2 | RSS job |
| RSS per **idle** open session | measured at M3; pinned; 10,000-session row derived | RSS job |
| Cursor + credential budget | node-global, `max_inbound_concurrent × 64 KiB` (unbounded at 0 — PB-18; the 15 MB figure is a measurement, not a cap); 64 KiB cap per connection, lazily grown; `spill_budget` is separate and outside the headline row | RSS job |
| Emission queue | ≤ 200 ms of frames per stream | RSS job |
| Idle RSS | ≤ 1.5.5 measured (recorded at M1) | RSS job |
| Static binary size | tracked M1–M3; ceiling set at M3, then gated | size job |
| Heap allocations per one-shot unit outside the arena (scope: process allocator on the Teller path; TLS handshakes, pool warm-up, third-party init, and the one boxed transport future per call excluded and listed) | **0** (`FORWARD_PASSTHROUGH_MAX_ALLOCS` — 1.6.0-dev work, measured 87, gated 107 → ≤ 20 at M4 → 0 at Phase 0.5 exit); per session as well | `alloc_gate` built into the gate with a match-count floor |
| JSON span scan | ≤ 1 µs per KiB of scanned prefix (pinned target: one pass, no allocation, ≈ 1 ns per byte on the reference profile), measured at M1 | scanner micro-gate |
| Time-to-silence after a supersede CAS | ≤ `interrupt_deadline`; frames emitted after = 0 | probe cell |
| WAL time-to-fill | `wal_capacity ÷ (rps × records per unit × record bytes)` — 4 GiB at the headline rate ≈ 35 s (hence the null-sink export in the profile); at 1k rps with 512 B records ≈ 70 min → the boot warning (a `data_dir` deployment only, PB-17) quotes this number | sizing artifact + boot warning |
| Journal volume and retention | (2 records per one-shot unit + 1 per further leg + 1 `Slice` per top-up + 1 `Lease` per capped-`concurrent` bucket per unit) × rps + sessions_with_accrual × 1/`tick_interval` × record bytes (≤ 512 B per record, continuations counted; measured at M2) → published daily sizing per store and the retention horizon | sizing artifact |
| Independent recompute cost | the node Tick recomputes every posting since the recompute watermark (≈ 120k/s at the headline rate) — p99 CPU share measured at M2, pinned | recompute job |
| Hot-path contention | one WAL sequencer per node; session table node-global sharded; per-core slabs, lazily grown, carving the per-unit 4 KiB arenas (never pre-carved to `in_flight_cap`); slice counters node-global atomics | contention artifact |

**One durability mode. No flags.** Two group-commit waits per one-shot unit.

**Hot-path rules for builders** (gated): no allocation outside the arena in steps 0–7; no `String`
formatting, no `serde` to text per unit; records fixed-layout; locators pre-compiled and incremental;
the registry immutable within a generation; frames borrowed on relay; the credential copy is in the
connection slab, the peer copy in the peer slab; arenas reset per unit (per frame on the relay path); facts maps pre-allocated.

**Configuration compatibility — the parity clause, mechanically.** A 1.5.5 `config.yaml` boots and
SERVES 1.6.0 unchanged: every one of the 205 inventory keys keeps its default and semantics; every one
of the 228 boot refusals and warnings fires on the same condition with the same message and no other
refusal OR WARNING can fire on a 1.5.5 config (§4.8 part (b) fires only on 1.6.0-additive keys); a 1.5.5
`plugins.yaml` loads through the per-kind ABI adapters; no `data_dir` is required; the two listeners
and the admin mTLS guard are as in 1.5.5. **Where 1.5.5 blocks land**: `listen`/`admin_listen`/
`admin_tls`/`admin_require_mtls` → the listener axis (two listeners, admin claims only on the admin
listener); `models`/`pools`/`groups`/`limits`/`rate_card`/`per_request_fee`/per-lane
`max_requests`/`max_concurrent`/`default_max_tokens`/the SSRF guard keys (global, catalog default,
per-provider override replaced-not-merged) → kernel config (`Policy`); `providers.*` credentials,
`tls`, `admin-tokens` and every `SecretRef` (`{env:}`, `{file:}`, module) → the egress-auth,
transport-key and auth units through the secret plugin; `hooks` → the four seats with each migrated
hook's `on_error` chain, `on_empty` terminal, `may_change_destination = true` and
`max_priced_delta = unbounded` sealed at `Migration`; `plugins` → the adapters; `store` → the store
plugin (memory default, persisting nothing; the four 31-day / 256-write sweeps — `put_key` tombstones, `put_credential` revoked-only, `add_usage` rows by `window_start`, `add_metering` rows by bucket age — plus the idle uncapped all-time cell sweep (a `dirty` cell is never swept), verbatim; `put_usage` rows, live keys, live credentials and the denylist are never swept, PB-38); `config` (`locked`, `overlay`, `overlay.file`, `BUSBAR_CONFIG_OVERLAY`, `--safe-mode`) → the overlay subsystem verbatim (PB-49); CLI, env precedence, `RUST_LOG`, `--migrate-config` → PB-50..PB-52.

**Behavioural changes: NONE user-observable.** Every candidate change found in twenty-five audit
rounds was reverted to the 1.5.5 rule by the parity clause; the ledger keeps the stricter rule
INTERNALLY: admission decision (check-then-charge, cents-truncated compare with fee lookahead,
post-hoc token cap, concurrent gauge — the hold is accounting, never a gate); zero billing when the
upstream reports no usage (the kernel floor is internal evidence only); `requests` charged at
admission and never refunded, `billable_requests` refunded on non-2xx (fee on 2xx headers, never
reversed); pool-scoped charge and refund on the selected pool only; `max_hops + 1` failover
attempts; the pool-empty 503 without `Retry-After` and the exhausted 503 with one; auth hard-down
rendered ingress-native; the one-dialect quota 400 (inventory G2); the `/usage` fee base on admitted requests and per-row
truncation; per-node in-process idempotency cache (mint twice across nodes, as 1.5.5); existence-only
parent check on admin mint; unbounded pool candidate sets; spill sized to 1.5.5's buffering; serve-
through on any store outage for peerless deployments (write-behind, reconcile later); no new boot
refusals; every 1.5.5 dynamic plugin loads; historical `/usage` figures reproduced by the legacy
projection byte for byte, INCLUDING retroactive repricing at read time when the card changes (the immutable figure lives on new endpoints); every metric name, type (the duration SUMMARY), label and help text; every
log line and span field; every CLI flag, env var and exit code; `/healthz`, `/stats`, `/metrics`
(key-authed, served by the built-in export plugin) unchanged — each with a §8.1 cell: CLI flags and exit codes, env vars and their precedence, SIGHUP-not-handled, the 25 startup steps, the seven `#[instrument]` spans and the request-log record are oracle cells diffed against the 1.5.5 binary (PB-54). The 1.6.0 verbs, the dual-control
posture, the operator key, the journal, chains, checkpoints, anchors and the disputes report are
NEW SURFACE reachable only through new endpoints and new config keys; nothing 1.5.5 exposes gains or
loses a byte.

**The one additive difference, left for the owner**: with `data_dir` configured, a memory-store
deployment retains ledger history across a restart, so `/usage` after a restart shows history where
1.5.5 showed none. Without `data_dir` (the 1.5.5 shape) behaviour is identical. Default: identical
(no `data_dir`); the owner may opt in.

**Admin API — byte-identical.** Every 1.5.5 operation (66 at the tag) returns the same bytes for the same state — with the two stated exceptions, BOTH now version-reporting: `GET /admin/openapi.json` (PB-75, served byte-identical except `info.version`, which reports `CARGO_PKG_VERSION`) and `GET /admin/info` (ADM-042), whose `version` is `CARGO_PKG_VERSION` and whose `build { auth_modules, hook_plugins, weighted_floor }` reports the running binary, the same shape with the running values —
same request under `single` (the migrated posture): `/usage` carries NO additive lines (1.6.0 ledger
facts live on new endpoints), the legacy projection reproduces the per-row truncate-then-sum and the
admitted-request fee base, idempotency is per node. The 17 new verbs and the `required` posture are
additive surface no 1.5.5 client can reach.

---

## Appendix A — Owner decisions register
Units decide, core sequences · planes return facts/locators only · every unit runs all 7 steps · all
three surfaces every cell · agents build, integrator gates, Fable verifies · reference plane first, voice
after the performance sprint · oracle in Rust · nothing deferred · multi-node is the design · voice
scope: OpenAI Realtime over WS + WebRTC (terminated), Gemini Live egress, one-shot transcribe/TTS,
Twilio Media Streams in, **raw SIP out** · tools relayed and via MCP · audit record fixed for every
plane, content never in the chain · open vocabulary, closed shape · one durability mode, no flags ·
≥ 120k rps and ≤ 15 MB are gates · zero config changes, admin API a superset, single-admin operating
model kept · **residual risk accepted under `single`: a single admin can change prices, destination
allow-lists, hook destination steering, unpriced admission, fail-open hook policy, revocation grace, and
adjustments below `adjust_threshold`, `set_overdraft_ceiling` and `grace_slices_per_window` (the two knobs that let money move past a cap), `set_dispute_max_age` (which can hide overdue disputes), and `tier_bp` (which moves every posting in its chain, bounded ≤ 10×, a ledger-endpoint line (PB-16)) — journaled, alarmed and shown on the ledger endpoint (PB-16); and on an upgraded
fleet, until the operator-key ceremony runs, `set_operator_key` is admitted with the admin credential
alone and the binary-digest set is `any` (the root of trust and the binary attestation are open to
whoever holds admin during that window, and `export_keyset` seals the keyset to any recipient key that
admin names — journaled, alarmed, on the ledger endpoint (PB-16)); and hooks migrated from
1.5.5 keep their unbounded price and destination influence; migrated planes' `unpriced_classes` serve
at 0 until priced; and under BOTH postures ANY token-exchange principal mints `user:*` template
instances without a second approver, unbounded when `max_auto_provisioned_groups = 0`** ·
the default anchor is
self-attestation and says so · the ledger posts the lower evidence and reports within `dispute_max_age` ·
**maximum-spec-compliance (owner rule):** where the published 1.5.5 bytes deviate from a provider's
own published spec, the spec wins and the difference is registered in `accepted-differences.json` as
`improvement` (owner sign-off, named in the CHANGELOG) rather than reproduced as a bug — first cases:
Bedrock text content blocks emitted without a `contentBlockStart` frame, the Responses door's
lifecycle frames, the required response/stream members added on every dialect, and every stream
request on the Responses door answered as an actual stream (never plain JSON) · the Anthropic
cross-protocol `ping` STAYS (a named, accepted gap against the published spec, not a defect to fix) ·
a fallback-lane stream is billed the same as a hot-path stream — `stream_options.include_usage`
injection is unified onto the degraded/fallback path so a fallback stream to an affected lane no
longer bills zero tokens — registered as `improvement` (owner sign-off; money-affecting) ·
busbar is a byte-governance router.

### Decisions 2026-09-05 (orchestrator, resolving the consolidated contract gaps in `docs/design/1.6.0-contract-gaps.md`)

- **CG-20 `KernelSeal` means one thing.** The caps unit struct. The contract's trait of the same name
  cannot be removed — `busbar-caps` implements it on every token and sits above the contract, and Rust
  has no "implementable by exactly one other crate" — so what is done instead is: it leaves the
  contract's ROOT re-export (reachable only as `busbar_contract::plugin::KernelSeal`, pinned by a
  `compile_fail` doctest with a positive companion so the fixture is not read as claiming
  unnameability), and the `kernel-seal-impls` construction-gate rule forbids implementing it in-tree
  outside `busbar-caps`, over test code as well as production, with a named ratchet for the ten files
  that carry one today. §3.7's row is amended to "compile-time for caps-token holders + CI scan
  (in-tree)" rather than "compile-time", because that is what the mechanism is. An out-of-tree plugin
  can still implement the trait; it cannot obtain a token, because the manifest allow-list (which reads
  `[dependencies]` only) refuses a plugin crate that names `busbar-caps`, and a loaded plugin is
  trusted code in any case.
- **CG-28 `busbar-caps` depends on `busbar-contract`.** One spelling of every seam type; the caps
  stand-ins are deleted. §3.1's "std and nothing more" for caps is amended to "std and the contract".
- **CG-37 the store trait is typed after the published ABI-2 store protocol** (the request/response
  shapes the shadow oracle already proves against the released stores), extended with the 1.6.0-only
  operations §1.4 names. No signature is inferred from prose.
- **CG-17 the MCP mount is fixed at `/mcp`.** A configured canonical address naming another path is a
  boot refusal at config validation. Claims stay compile-time constants; there is no registration-time
  selector.
- **CG-22 ceilings count surface code**: non-blank, non-comment `src/` lines excluding test modules.
  Proofs (totality tables, lint data, fixtures) live under `tests/` or `fixtures/`. If contract + caps
  still exceed 3k after the move, §1.1's figure for the pair is amended to the measured number rounded
  up to the next 500, and the per-file table stays.
- **CG-41 an unreconciled amount is a move out of settled**, not a parallel tally: `unreconciled += A;
  settled -= A`. §4.2's identity closes with no special case and nothing is reported as settled that the
  store has not confirmed.
- **CG-56 the seventeen 1.6.0 kernel verbs bind as `<kebab-case-verb>` under the admin prefix**: POST
  for every mutating verb, GET for `verify` and `plane_facts`.
- **CG-55 the anthropic error envelope's minted request id keeps its native shape and entropy**, and the
  entropy comes from the kernel through `Ctx`; a plane still reads no random source of its own.
- **CG-06 config-derived open-vocabulary keys are leaked exactly once at registration** by the
  composition root and counted in §10's fixed RSS term (the `&'static str` ids stay). A per-dial leak
  is a defect.
- **CG-22 / CG-05 (2026-09-05, second decision): the contract pair stays under 3.5k by crate boundary, not by
  leaving proofs in planes.** The closed JSON span grammar (the kernel's scanner, ~300 surface lines) becomes
  `busbar-grammar`, std-only, ceiling 0.5k, re-exported by `busbar-contract` and named by the kernel, so the
  four plane copies collapse to one. The transport-facing contract (the `Transport` trait, wire types, the
  upstream address, the reserved fact keys) becomes `busbar-contract-transport`, ceiling 1k: a plane author
  never reads it (transports are in-tree), which is what the pair's ceiling measures. `busbar-contract` +
  `busbar-caps` stay at 3.5k of plane-visible surface.
- **CG-62 (2026-09-05): overlap is resolved by precedence before it is refused.** Two path-family claims of
  different specificity overlap by the conservative rule and are resolved by the sealed most-specific-wins
  order; only an overlap at equal precedence between claims whose scheme sets are compatible is a boot
  refusal. Claims with disjoint scheme sets never overlap. **CG-63:** a claim on a transport that has no
  crate is a boot refusal; the voice plane's telephony claim waits for its transport (Phase 0.5).
- **CG-51 the network guard is the trust unit's check** over `VerifiedDestination`, applied before any
  transport `dial`; transports do no resolution policy of their own.
- **CG-51 / CG-28 (2026-09-05, status): one address judgement, two spellings still.** The guard's
  ordering now lives once, in `busbar_unit_trust::net::check_destination_facts`, with the sealed-value
  entry `check_destination` a projection onto it — a composition root judges a candidate BEFORE it is
  sealed, so it holds facts and no seal, and given only the sealed entry it wrote the ordering out a
  second time. The A2A root's copy is deleted. The copies had already drifted: the root's accepted a
  bare `user@agent.example:443`, whose two readings differ, where the trust unit refuses it. What is
  NOT done is CG-28's one-spelling merge of `VerifiedDestination` itself: the caps stand-in carries a
  lane and the contract's carries `DestinationFacts`, and two composition-root seal sites
  (`root/units_llm.rs`, and the LLM walk behind it) hold only a `LaneId`, so sealing contract facts
  there would fabricate an `UpstreamAddress` or intern one per request against CG-06. The caps
  accessor is also infallible where the contract's is `Option<LaneId>`, which three tests depend on.
  The merge waits on the LLM root naming a real per-candidate address. Until then CG-51's compile-time
  link — the value the trust unit seals IS the value a transport dials — remains unmade, and the
  guard's remaining copies in `busbar-substrate`'s `net_guard` and `busbar-llm`'s engine egress are the
  next step of the same collapse, onto the unit and not away from it.

**2026-09-05 — the contract/caps LOC ceiling counts surface, not proofs.** The ceiling in §1.1 is a
budget for what a plugin author has to read: non-blank, non-comment code lines under `src/`, with
`#[cfg(test)]` modules and `src/tests/` excluded. Data that exists only to PROVE a property — the
overlap totality table over the selector-form pairs, the lint symbol lists, the compile-fail fixtures
and their positive companions, the honesty tables kept as documentation — is a proof, not surface,
and lives in the crate's `tests/` or `fixtures/`. Measured that way and with the lint lists moved out
of `src/`, the pair is 3,281 lines, so the ceiling is amended from 3k to **3.5k**. The reason it does
not fit in 3k is the design's own requirement, not slack: `Selector::overlaps` must be TOTAL over the
cross-product of the thirteen selector forms — 169 pairs — with no catch-all that panics, and the
loop's step order is carried by types: ten step markers, and twelve token types that name the step or
the unit they entitle. Totality and type-level step order are what the surface costs.

## Appendix B — Parity bindings (override any conflicting sentence in §1–§9 for every 1.5.5-reachable surface)

**PB-0 (master rule).** EVERY row of every inventory file under `inventory/` is a parity binding and an oracle cell, whether or not it is restated below: the 1.5.5 behaviour it cites is reproduced byte for byte on every 1.5.5-reachable surface. Appendix B restates only the rows where a sentence in §1–§9 needed an explicit override or where a reviewer found the transcription worth pinning; absence of a row from this table binds nothing looser. Where a binding paraphrases its row imprecisely, the row wins (PB-72). Consequently the reviewer's question for §1–§9 is only: does a body sentence introduce a user-observable behaviour that contradicts an inventory row without an override here?

Each binding names the inventory row it reproduces. Where a sentence elsewhere in this document
describes a stricter or different rule, that rule is INTERNAL (ledger, journal, new planes, new
endpoints) and this binding is what a 1.5.5 user observes. The §8.1 cell for each binding diffs the
published 1.5.5 binary.

| # | Surface | Binding (1.5.5 rule, reproduced) | Inventory |
|---|---|---|---|
| PB-1 | hook `on_empty` | default `reject` (fail-closed) when the gate declares none: 503 `KIND_OVERLOADED` "No upstream satisfies a required gate's restriction. Please retry shortly."; on the restrict-empty arm `first` takes the SAME 503 (1.5.5 branches only on `Weighted`); `weighted` only when written, per PB-28; `first` orders only as an `on_error`-chain terminal; sealed per migrated gate | proxy-hooks §2.4 (`engine/mod.rs:1055-1082`), config CFG-227 |
| PB-2 | per-lane `max_concurrent` | fail, never wait: `try_admit` → `AtCapacity`, the lane is skipped within the pick; waiting only under `on_exhausted: queue { max_ms }` with 1.5.5's semaphore | proxy-hooks §2.7, governance 4.2.5 |
| PB-3 | tripped / budget-exhausted / at-capacity lanes | EXCLUDED from the walk exactly as `try_admit` excludes them (never "ordered last and attempted"); all excluded → the pool's `on_exhausted` terminal after the `requests` charge | proxy-hooks §2.7 step 6, §3.5, §3.6 |
| PB-4 | `on_exhausted` terminals | default (key absent; `Status503` is the variant name, not a config spelling): 503 + `Retry-After` = the soonest GENUINE (> 0) cooldown among `lane_admissible` members as-is, else `AT_CAPACITY_RETRY_AFTER_SECS` = 2, the whole `.max(1)` · `least_bad` (one breaker-bypassing attempt) · `{ fallback_pool }` (cross-pool hop, restricts re-applied, plain SWRR, multi-level, visited guard; the charge follows the ATTEMPTED pool — PB-47) · `{ queue: { max_ms } }` (FIFO permit park ONLY if some exclusion was `AtCapacity`, else the 503 immediately; the winner re-checks `try_admit_breaker`; `busbar_pool_queued` gauge) — implemented by the egress unit's walk | proxy-hooks §2.11 (`walk.rs:49-65`, `:176-334`), config CFG-096..100 |
| PB-5 | pick order | sticky-affinity fast path (`hash % cands.len()`, skipped on weight 0 or excluded lane); hooks stable-sorted by `priority`, globals first then config order; the LAST ordering gate wins, re-validated against the final post-restrict set, empty ⇒ abstain; at pick time a ranked lane is taken only if it is in this hop's candidate set, has non-zero weight and passes the side-effect-free `ready_in` peek — if none qualifies, fall through to SWRR over the same candidates (`select.rs:361-394`); base policy only when no gate ordered; then the SWRR floor | proxy-hooks §2.4, §2.7 steps 2 and 5b, §7.7 |
| PB-6 | hook seats for migrated hooks | every 1.5.5 hook runs AFTER the governance charge (rewrite, request taps, gates, base policy are all post-charge); a rewrite-gate `Reject` or a decision-gate reject consumes the `requests` slot (billable refunded); request-stage taps are `notify` only — fire-and-forget, reply ignored, errors swallowed (`fire_global_taps`) — and can never reject | proxy-hooks §2.1, §2.2 |
| PB-7 | inbound shed | `max_inbound_concurrent` covers EVERY data-listener route (`/stats`, `/v1/models`, `/v1beta/models`, `/metrics`, `/metrics/hooks`, `/auth/token`, `/healthz`); the static 503 body + `Retry-After: 1`; the admin listener is never capped | routes-admin LST-001, ops §3 |
| PB-8 | request bounds for `http`/`sse` units | only 1.5.5's: `failover.timeout_secs` (120 s walk deadline, checked UNCONDITIONALLY before every attempt streaming included → 503 + `DETAIL_REQUEST_TIMEOUT` on the pre-attempt check; the `pick_among` guard instead returns `None` and lands on the pool's `on_exhausted` terminal (503 `KIND_OVERLOADED` + `Retry-After`)); the per-request reqwest timeout applied only when NOT streaming; per-attempt time-to-headers cap with pool-member override; `upstream_request_timeout_secs` (default 300, no ceiling — the client-level TOTAL deadline that also bounds streams); `max_hops + 1` attempts; `failover.exclusions`; context-length exclusion of every candidate whose `context_max` <= the failed lane's (a `None` failed limit excludes only the failed lane, `engine/mod.rs:2099-2120`); NO `max_unit_duration` cut and NO drain deadline (SIGTERM drain is unbounded, streams run to completion); `max_unit_duration` is the stall sweep only (PB-48) | proxy-hooks §2.8 rows 1 and 12 (`engine/mod.rs:1363-1373`, `:1694-1698`), ops §3.6, config CFG-130 |
| PB-9 | revocation / rotation | gates NEW units only; in-flight `http`/`sse` units run to their 1.5.5 end (no tick abort); rotate has no grace; on the serving node the old token dies at once via the generation gate; on OTHER nodes exactly PB-45's mechanisms and bounds (denylist re-sync 5 s TTL ≈ 10 s in practice for revoke; `by_id` refreshed only on a local mutation or restart for rotate and `enabled=false`) | auth-secrets :551 (note), :155-161, :593-594 |
| PB-10 | upstream disposition and status mapping | the 31-row table (`TransientUpstream` / `HardDown` billing vs auth / `ContextLength` / `ClientFault` / passthrough 401–403, breaker records, metric labels, `kind` and detail literals) reproduced verbatim, one cell per row | proxy-hooks §2.8, §3.4 (`:377-407`) |
| PB-11 | plugin trust and ABI windows | `plugins.trust` verbatim: publishers allow-list, embedded first-party key, `allow_unsigned` / `allow_third_party` (default false; unsigned or unknown-publisher plugin LOGGED and SKIPPED with the literal messages, never dlopened), `UntrustedFloored` never relaxed, catalog verdict strings; the operator-key digest set is an ADDITIVE 1.6.0 layer; every plugin within its kind's 1.6.0 window (store [2,4] — OWNER DECISION: widened past the published-1.5.5 floor of [2,2] because ABI-4 stores are a later release and must load on this binary too, not a 1.5.5-parity constraint; auth [1,2], hook [1,1], export [2,2], secret [1,1] unchanged) loads through its ABI adapter (no "floor 5" precondition anywhere); `supported_abi(kind)` REPORTS the current window — boot, `--validate` and `POST /plugins/inspect` print `v2..=v4` for a store, never `v2..=v2` and never `v2..=v5`; a published-1.5.5 store (ABI 2) and an ABI-4 store both load; ABI 3 remains inside the window; `plugin-pack --abi-version` defaults to the 1.5.5 max; `TRANSPORT_VERSION = 1` is checked FIRST in `wire_up_raw` and stays 1 with the six kind-neutral symbols; `plugins.fetch` runs before preflight at boot (`fatal_on_miss`) and on reload (warn-and-keep), verify-before-write, never under `--validate`; a manifest OUTSIDE that window is refused with 1.5.5's literal `manifest abi_version {n} is not supported for kind '{kind}' by this binary (supported range v{floor}..=v{max})` printing the CURRENT range, never `PluginAbiTooOld` | config CFG-184/185, plugins-stores :195, :224, :2000 (`plugin-sign/src/lib.rs:611-615`) |
| PB-12 | export subsystem | the built-in `export:` sinks (`prometheus`, `request-log-webhook`, `request-log-file`, `otlp`) are fire-and-forget at-most-once: never block the request path, never surface errors; the webhook admission gate is PER INSTANCE (`tests/webhook_tests.rs:222-268` at the tag proves it; CFG-249's "shared" wording is the defective row and is corrected in the inventory); `PRODUCED_STREAMS` and the validate-time refusals verbatim (`costs` / `decisions` / `identity` / `prompts` / `completions` rejected with the 16 literals, `fields:` exhaustive never additive, `buffer_seconds` required, `key_gauge_limit` 2000) — 1.6.0 never makes a refused stream name start producing; the file sink uses the fixed `MAX_INFLIGHT_FILE_APPENDS = 64` and ignores the key; `durable: true` a config refusal; `OnceLock` process globals; restart to repoint; a migrated export PLUGIN (none ship at the tag) keeps at-most-once, no-ack, no-retry and is not called on the data path; `Segment`, ack and retry exist only for 1.6.0-native export plugins | plugins-stores §4 (:1510-1545), config CFG-249, :2367-2371 |
| PB-13 | `data_dir` | DEFAULT UNSET; no data-dir probe, no data-dir files, no `DataDirNotWritable`, no `KeysetMissing`; the 1.5.5 overlay file `busbar-overlay.json` beside the resolved `config.yaml` and its boot writability probe (BOOT-W18) are unchanged (PB-49); the journal is memory-buffered and shipped to the configured store; the deployment keyset is sealed in the store ONLY where the store can hold it (a 1.6.0 native-ABI store); on a 1.5.5 ABI-2 store (which has no such method) and on the memory store the keyset is node-local and ephemeral and NOTHING depends on it on a 1.5.5-shaped deployment — no fingerprint check, no `KeysetMissing`, no ceremony — a node joins by starting with the shared config and store (rolling start); the WAL, local keyset, probe and import exist only when `data_dir` is written | plugins-stores :945, ops :208, config CFG-009 / :744 |
| PB-14 | store outage, peerless node | serve-through: cells stay authoritative, admission never blocks or fails on the store, deltas retried each tick, reconcile when it returns; `/usage` returns `AdminError::Internal` (500) while the store is down; boot fails closed on a store error at hydrate; no drain, no `outage_grace`, no `StaleSlice`, no new-draw refusal — the fleet branches of §2.3/§4.6 apply only when `peers:` is written | governance 7.4.1–7.4.5, 7.5.3 |
| PB-15 | WAL high-water | never refuses admission on a 1.5.5 config: without `data_dir` there is no WAL; with an explicit store the discard posture is sealed for every migrated config | governance 7.4.1 |
| PB-16 | `/usage` and every legacy admin response | byte-identical; NO additive lines — every alarm or delta named "on the ledger endpoint (PB-16)" in §4.2/§4.7/Appendix A lives on the 1.6.0 ledger endpoints (`/api/v1/admin/ledger/*`); a legacy metering row (`requests`, `spend_micros`, tokens) is written ONLY by the delivered-response tap — an admitted-but-undelivered unit (pool-empty 503, deadline 503, rewrite 500) writes no row and its fee is refunded on the non-2xx status; a terminal-error stream (delivered on 2xx headers) writes no token line and no legacy metering row but KEEPS the flat fee | governance §6, 7.3.1, 5.2.11, 6.3.3 (`proxy/usage.rs:57-107`), routes-admin ADM-* |
| PB-17 | boot warnings | none beyond 1.5.5's 228 unless a 1.6.0-additive key (`data_dir`, `peers`, `keyset_ref`, `wal_capacity`, …) is written | config §3 |
| PB-18 | arrival budgets | `spill_budget` = `max_inbound_concurrent × request_body_max_bytes`; cursor and credential budgets = `max_inbound_concurrent × 64 KiB`; `max_inbound_concurrent: 0` ⇒ every derived budget UNBOUNDED (1.5.5: no layer is added, BOOT-089e); the per-unit arena holds only per-frame transform output — relay and egress bodies live in the connection slab / spill — so neither the arena nor any budget refuses a request 1.5.5 accepted; the tighter RSS bound is the §10 gate, not a refusal | config CFG-131, CFG-134 (:267) |
| PB-19 | `MissingGroup` | a key bound to a group absent from this node's config fails closed: `insufficient_quota`, 429 (400 on the one dialect), literal message | governance §3.2.1, §3.6.7 |
| PB-20 | admin audit chain | 1.6.0 keeps APPENDING the legacy `AuditEntry` chain: 8 WIRE fields (`recorded_here` is `#[serde(skip)]`), 33 action names, `hash` = SHA-256 hex over the canonical `prev|seq|ts|action|resource|outcome|principal`, genesis `prev_hash` = the empty string, 1000-entry ring, `restore_from_store`, so `GET /api/v1/admin/audit` continues unbroken byte for byte; the journal is additional | routes-admin §6 (:648-669) |
| PB-21 | idempotency | per node, in process, TTL 600 s, `(actor, header)` / `(actor, "rotate:{id}:{k}")`, no body hash; the in-flight arm: a `Null` sentinel reservation, a concurrent duplicate ⇒ `409 {"error":{"code":"conflict","message":"a request with this Idempotency-Key is already in flight"}}`, `Reserved` cleared on `Drop`, `InFlight` deliberately not; a replay returns the original `201`/`200` with no replay-marker header; a retry on another node mints twice | routes-admin §4 (:305-311), auth-secrets §3 |
| PB-22 | admission decision | CHECK-THEN-CHARGE under one set of shard guards: pass 1 checks every bucket of the pool-filtered chain and returns on the FIRST blocking bucket in chain order (metric priority `requests` → `tokens` → `budget`; that bucket names the 429 message and `Retry-After` scale), charging nothing — preceded by the phases OUTSIDE the shard guards: `MissingGroup` → FREEZE (403 `permission_error`, before any gauge or charge) → the `concurrent` CAS (429, its own message, `retry_after: None`) — PB-79; the Bedrock 400 (`quota_exceeded_status()`) applies ONLY to `budget` (`insufficient_quota`) and `MissingGroup`, never to `requests`/`tokens` (always 429 `rate_limit_error`); pass 2 then adds `requests` and `billable_requests` +1 on EVERY bucket of the chain (uncapped key bucket included; `capped_bucket_ids` is only the sweep-exemption set) and the fee lookahead; `budget` as `derived_cents >= cap \|\| derived + fee > cap`, `tokens` post-hoc, `concurrent` gauge, pool scope, downgrade cascade, frozen groups; the hold is accounting only | governance §3.1 (:196-197), §3.3 (:218-231), §3.4, 3.4.3, 2.7.2, 2.6.1 (`state.rs:1757-1849`) |
| PB-23 | `--safe-mode` as first argument | exits 2 ("unrecognized argument") — reproduced; fixing it is an owner decision recorded here as OPEN | ops §2 |
| PB-24 | listeners | two listeners always, admin claims only on the admin listener, `admin_require_mtls` guard | routes-admin LST-001/002 |
| PB-25 | usage absent from a stream | bills zero; kernel floor internal only | dialects §4 |
| PB-26 | pre-charge vs post-charge exits | every `finish_rejected` exit charges NOTHING: the governance guard in 1.5.5's order — pool-ACL 403 → reachable-fallback-pool ACL 403 (`fallback_pools_authorized`, visited-set guard) → no-rate 400 `invalid_request_error` "no configured rate for model '{pool}'" → admission 429 — plus malformed / non-object body 400, a MISSING `model` 400 `invalid_request_error` (`dispatch.rs:136-155`), the ad-hoc provider mismatch 400 (`ingress/mod.rs:1368-1393`), the two further 400s at routes-admin :222/:224, an unresolved name 404, unsupported path/action 404; every exit AFTER `governance_guard` retains the `requests` slot (`billable_requests` refunded on non-2xx): the priced-but-unrouted 404 through `finish_admitted`, rewrite 500, deadline 503, pool-empty 503, engine and upstream ends | governance §3.1 steps 2–4, §3.6.1–3.6.2, §3.8.5–3.8.7 (`ingress/mod.rs:39-90, 362-394, 491-518`; `dispatch.rs:199-235`) |
| PB-27 | zero-token ends | a response bills ZERO tokens (located and accrued figures internal evidence only) on every 1.5.5 not-billed arm: a stream ending with a terminal error signal (`terminal_error != None`); an SSE transport cut after the first byte (`stream_failed = true`); a buffered cross-protocol 2xx that fails after the upstream 2xx (transport failed mid-read → 502, over the translate cap → 500, untranslatable → 500); the `max_requests` lane unit is refunded on the pre-first-byte cut and the client disconnect, NOT on the post-first-byte transport cut; a client disconnect bills the partial tokens and refunds the LANE `max_requests` unit; the flat fee (`billable_requests`) is KEPT, as on every exit after 2xx headers were relayed (`ingress/mod.rs:574-579` refunds only on a non-2xx client status) — each arm one cell | dialects §4.4; proxy-hooks §4 (:430-436; `engine/mod.rs:329-378`, `:552-589`, `response_body.rs:283-345`); governance 3.8.4 |
| PB-28 | `on_empty: weighted` semantics | for a GATE: that gate's restriction is skipped and the candidate set is unchanged; for the BASE POLICY: escape to full-pool SWRR; never "the full verified set" for a gate | proxy-hooks §2.4, §2.5 |
| PB-29 | gate vs routing-policy 503 literals | four distinct bodies reproduced: "No upstream satisfies a required gate's restriction…" / "No upstream satisfies the routing policy's restriction…" / "A required gate could not complete…" / "The routing policy could not select an upstream…", keyed on whether the failing hook is the pool's base policy or a decision gate | proxy-hooks §7 |
| PB-30 | protocol detection | the 14-rung `detect::protocol_id` ladder verbatim (header presence `anthropic-version` or `anthropic-beta` / `x-api-key` / `x-goog-api-key`; header prefix `AWS4-HMAC-SHA256`; path suffix / contains `…/v1/chat/completions`, `:generateContent`, `/converse`; the catch-all route); an unmatched path renders the PATH-INFERRED protocol's 404 (`proto_for_path`, which may differ from the detected protocol — `/v1/models/{rest}` detects gemini, renders openai); on the DATA listener any path equal to `/api` or under `/api/` gets the frozen admin envelope `{"error":{"code":"not_found",…}}` from `fallback_error_response` (three call sites: the data catch-all, `method_not_allowed_handler`, and `reshape_oversized_413` — the last on BOTH listeners) BEFORE `proto_for_path`; the admin listener's own route fallbacks are PB-76 | dialects §2.1(a); routes-admin RT-013, RT-040 (:197), :261-264 (`main.rs:1195-1205`) |
| PB-31 | plugin-declared routes | `plugin_routes` verbatim: `/hooks/{owner}` or `/hooks/{owner}/*`, `/exports/{owner}` or `/exports/{owner}/*`, `/metrics`; `RouteAuth` incl. `None`; empty-body 405 and 404; the three 502 arms, of which the `DynExport::Err` 502 carries the loader's error text as its body; the 64-header cap; kernel-mounted from the declared table (the no-self-mount rule carves these out); a newly declared plugin route path is RESTART-scoped (PB-39) | routes-admin RT-011 (:129, `plugin_routes.rs:101-111`), RT-012, §5.8 |
| PB-32 | admin mutation rate limiting | `admin/rate.rs` verbatim: 60 s windows, `Config` 10/min, `Crud` 60/min, `PluginInspect` 30/min, `429 {"code":"rate_limited"}` + `Retry-After: 60`, enforced before the handler, first denial per window audited | routes-admin §4 |
| PB-33 | `GET /auth/token` | the browser exchange verbatim: unauthenticated exact-path bypass, `200 text/html` or `302` to the IdP, `?logout` / `?code` / `?method` / `?refresh` dispatch | routes-admin RT-005 |
| PB-34 | secret-ref timing and value semantics | every migrated `SecretRef` resolves at 1.5.5's EIGHT sites with 1.5.5's caching and failure posture: `store.settings.*` (boot-real, reload WARN-only — BOOT-W15/BOOT-170); auth-chain / admin-chain / login-method settings (re-resolved at every chain build, hard error `auth/mod.rs:322-324`); the memoized `secrets:` open-config block; provider `api_key` once at app build, memoized for the app lifetime; TLS once per listener; hook settings re-resolved at every `gate_transport_named` / configure push; plugin-backed refs re-resolved on each `resolve()` (the plugin re-opened each time); the admin token and `auth.signing_key` re-resolved at boot and on every apply/reload that DECLARES the credential, through the deferred `GovCredentialRotation` closure (removal is restart-scoped — a reload deleting the declaration leaves the live credential and signer in place, :2000-2002); `export.<n>.settings.*` refs resolve core-side before crossing the ABI (config :1163); no TTL, no watcher otherwise; an unresolvable provider key is a WARNING degrading to `""`; built-ins (`env`, `file` — a strict two-way match) are unconditionally FIRST — a `kind: secret` plugin (incl. `secret-local`) can never shadow them; `{ literal: }` is NOT a `SecretRef` shape and is rejected by the schema at any `SecretRef` position (SEC-018/020); value semantics verbatim: `classify_setting` shape-only ordering with its one-level `{ literal: }` passthrough for non-secret settings, trailing `\r\n` trim, the empty-after-trim error text, fail-closed empties (SEC-020); `watch`/`refresh` are no-ops for migrated refs | auth-secrets §7.4 (:1854-1856), §7.8, §7.9 (:2005-2007); config SEC-001..020, :1145, :1177-1180 |
| PB-35 | auth chain and credential cache | `run_chain_cached` verbatim: config order, first `Identify` wins, `Reject` stops, `Pass` continues; `Open` ONLY when the chain declares no module AND no `keys` arm (`chain.is_empty() && !keys_in_chain`) — the mandatory in-tree `auth-lease` / `secret-local` plugins are NEVER members of the counted lists, so `auth.chain: []` stays anonymous-admit and `admin_auth: []` keeps `Grants::of(Scope::Full)`; all-`Pass` with a `keys` arm runs `keys_arm_verdict`, all-`Pass` without one is `Denied`; `auth_cache` only for modules whose `cacheable()` returns true (trait default FALSE — an external module that does not override it is re-verified every request), keyed `(module, sha256(cred))`, Identify TTL `min(ttl, 3600)` default 300 s, `PASS_TTL_SECS = 5` + jitter, `Reject` never cached, `MAX_ENTRIES = 4096`; the `keys` arm is cache-exempt; `POST /admin/auth/cache/flush` → `{"flushed": N}` with a real count; client credential carrier precedence `extract_client_token` verbatim: `Authorization: Bearer` → `x-api-key` → `x-goog-api-key`, a non-Bearer `Authorization` (e.g. SigV4) falls through to the next carrier — one cell per carrier pair | auth-secrets §2.1 (:58-70), §2.3 (:113, :132-134), §2.9 (:607-612), :1430 |
| PB-36 | `admin_auth: []` | open-admin posture: `principal == None` ⇒ `Grants::of(Scope::Full)`; the kernel-verb scope check is satisfied for `Principal::Anonymous` | auth-secrets :1430, :1537 |
| PB-37 | ABI-2 store adapter fallback | `call_with_legacy_default` verbatim: only `TransportErrorKind::Unsupported` opens a default, on `append_audit` / `list_audit` / `list_audit_tail` / `list_denylist`; everything else propagates | plugins-stores §5.8 |
| PB-38 | memory-store sweeps | the four amortised 31-day sweeps verbatim (strict `>`, every 256 writes per ticker): `put_key` tombstones, `put_credential` revoked-only, `add_usage` rows by `window_start`, `add_metering` rows by bucket age; the idle uncapped all-time cell sweep after 31 d — a cell survives while `still_enforces_a_cap || dirty || last_touch + max_window > now`; `put_usage` rows, live keys, live credentials and the denylist are never swept (the denylist has no bound) | plugins-stores §3.5 (:957-967), governance 3.2.8 |
| PB-39 | reload scope | RESTART keys exactly as the inventory: `listen`, `admin_listen`, `tls`, `admin_tls`, `admin_require_mtls`, `store`, `limits.upstream_request_timeout_secs`, `limits.pool_max_idle_per_host`, `limits.pool_idle_timeout_secs`, `limits.max_inbound_concurrent`, `advanced.response_headers.server_timing` / `.route_policy`, `advanced.worker_threads` / `.upstream_http1_only` / `.upstream_h2_prior_knowledge`, a newly declared plugin route path, the OTLP sink / `metrics::configure` recorder / write-behind flusher — `config/reload` stores but does not apply their deltas, does not rebind, rebuild the acceptor or re-open the store, and returns 1.5.5's `ConfigReloadView { reloaded, config_version }` unchanged (the `note` + `reload_to_apply` field list belongs to `PUT /config/settings` (`handlers.rs:2654-2662`) and the newly-declared-route `note` to the NAMED-MAP mutations (`named_map.rs:530-538`, `:643-649`) — each reproduced at its own handler); LIVE on swap: `limits.upstream_error_body_max_bytes`, `advanced.rate_sweep_interval`, `advanced.usage_flush_interval_ms` and every other key; `limits.request_body_max_bytes` HALF-LIVE exactly as documented | config §4.5 (:1046-1058) |
| PB-40 | unknown-key refusal | the serde `expected one of` list is byte-identical to 1.5.5's for EVERY `deny_unknown_fields` struct (all 49: the 44 enumerated at BOOT-P01 plus the five `section_patch!` twins in `config/patch.rs`, `GroupCfg` and `ChildDefault` included): every 1.6.0-additive key — top-level (`data_dir`, `peers`, `keyset_ref`, `wal_capacity`, `outage_grace`, …) AND per-bucket (`tier_bp`, `currency`, keyed by bucket name) — lives under ONE new top-level block `fleet:`, split off before the 1.5.5-shaped parse | config BOOT-P01 (:515), :67 |
| PB-41 | 1.6.0 warnings on 1.5.5 configs | the store record-rate warning and the `keyset_ref`-unset warning fire ONLY when `data_dir` or `peers:` is written; otherwise they are ledger-endpoint lines; PB-17 holds for every 1.5.5 key incl. `store.module` | config CFG-170, §3 |
| PB-42 | boot store probe | a migrated config boots on 1.5.5's read-only hydrate (BOOT-172/173 only); no write-read-back, so a read-only replica or grant-restricted DB boots exactly as on 1.5.5; the write probe exists only with `data_dir` or `peers:` | config BOOT-172/173 |
| PB-43 | operational routes | `/healthz` on both listeners with the unconditional auth bypass, 200 `ok` iff any lane passes the NON-MUTATING `is_ready_any_cell` over the default and every per-pool cell, else 503 `no usable lanes` (side-effect-free, never steals the single-flight recovery probe); `/metrics` is `text/plain; version=0.0.4`; `/metrics/hooks` is a CORE axum route (not a plugin route), `text/plain; version=0.0.4; charset=utf-8`, with its exposition contract verbatim (no prefixing, one `hook=` label, `busbar_`-prefixed dropped, bucketless histogram as summary, first-occurrence type wins, `HOOK_METRICS_TTL_SECS = 10`, `MAX_HOOK_METRICS 64`, the name regex); `/stats` per RT-* with its 20 per-lane fields, `"unbounded"` string, `Unavailable` variant names classified breaker-first, `recovery_hint_ms` floor 2000 — the 1.6.0 refusal vocabulary never reaches it; `/metrics` declared only when `export.prometheus` is configured, `RouteAuth::Key` (data-plane client token, not admin); `/metrics/hooks` mounted only when `metrics::enabled()`; `/stats` per RT-*; absent the gate, the catch-all 404 | routes-admin RT-002/003/004/012; ops §4.3 |
| PB-44 | `in_flight_reserve` | 0 unless a claimed transport declares `SESSION = true`; a 1.5.5 config sheds at exactly `max_inbound_concurrent`; the reserve is drawn only against session Unit 0 arrivals | config CFG-134 |
| PB-45 | revoke / rotate | applied SYNCHRONOUSLY on the node that served the admin call (the next request on that node sees it); on OTHER nodes exactly 1.5.5's mechanisms and bounds: revoke via the denylist re-sync (`REVOCATION_SYNC_TTL_SECS = 5`, scheduled on the blocking pool, so ≈ two windows ≈ 10 s in practice); rotate AND `enabled=false` (a reversible PAUSE, no denylist row — `admin/mod.rs:483-484`) via the store with the other nodes' `by_id` refreshed only on a local mutation or restart — so on a peer node the OLD token keeps verifying AND the newly returned token is REFUSED until then — reproduced; propagating faster is an OPEN owner decision recorded here (default: identical) | auth-secrets :155-161, :593-594, :551 (note) |
| PB-46 | migrated hook seats | a 1.5.5 `Request`-stage hook seats `After(Admit)` ahead of `Candidate` hooks, in 1.5.5's order; `Before(Approve)` is never used for a migrated hook | proxy-hooks §2.1, §2.2 |
| PB-47 | scoped draws and fallback | a scoped bucket is charged on the ATTEMPTED (effective, post-downgrade) pool — `attempt_pool`, which the refund also walks — "accounting follows the traffic"; a `{ fallback_pool }` hop draws and releases nothing | governance 3.9.7 (:334; `ingress/mod.rs:191-196`, `state.rs:1640-1641`), proxy-hooks §2.11 |
| PB-48 | stall sweep on `http`/`sse` | the `max_unit_duration` sweep alarms only; the unit's only timers are PB-8's — a stream is cut only by the `upstream_request_timeout_secs` TOTAL reqwest deadline (default 300 s, `main.rs:3179-3181`); there is no idle timer | proxy-hooks §2.8, ops §3.6 |
| PB-49 | config overlay subsystem | `config.locked`, `config.overlay` / `overlay.file`, `BUSBAR_CONFIG_OVERLAY`, `--safe-mode`'s function, BOOT-123/125, W18–W20, `NO_WRITABLE_OVERLAY_MSG` (wrapped in `AdminError::Validation` ⇒ 400 `invalid_request` at all five sites — `handlers.rs:461, 2093, 2492, 2951`, `named_map.rs:343`), persist-then-swap, tombstones, `0o600` — verbatim | config C3 |
| PB-50 | `--migrate-config` and the 1.x detector | 23 markers, 18 passes, YAML to stdout, banner to stderr, exit codes 0/1/2, no interpolation, comments destroyed, nothing written — verbatim | config C3, ops O1 |
| PB-51 | `RUST_LOG` | parsed as a bare `tracing::Level` only (no `EnvFilter`): `busbar=debug` falls back to INFO silently; the OTLP level floors at DEBUG independently | ops O4 |
| PB-52 | env-vs-config precedence | env wins for `BUSBAR_WORKER_THREADS`, `BUSBAR_UPSTREAM_*`, `BUSBAR_PROVIDERS`; config wins for `BUSBAR_CONFIG_OVERLAY`; the five deprecation warnings; the worker-thread chain `BUSBAR_WORKER_THREADS > advanced.worker_threads > TOKIO_WORKER_THREADS > available_parallelism() > 1`, `.min(128)`, `0` ⇒ warn and ignore, with W34's wording from `config.yaml` and CFG-293's wording from the env path | config §4.2 (:835), CFG-162, W34 |
| PB-53 | metric absences and gates | the five counters with no `describe_*` (no `# HELP`); the recorder installed only with `export.prometheus`; `busbar_billing_truncated_total` pre-registered `.absolute(0)`; the two retired names never reappear | ops O3 |
| PB-54 | CLI / env / signals / spans cells | §8.1 and `xtask gate` carry cells for every 1.5.5 CLI flag and exit code, env var, SIGHUP-not-handled, the 25 startup steps, the seven `#[instrument]` spans and the request-log record, diffed against the 1.5.5 binary — the 25 `run()` steps are an EXACT ORDERED sequence whose observable output is byte-identical (`busbar starting` stays the first log line; `Bootstrap` / `Migration` / `Policy` / keyset lines are DEBUG-level, never interleaved at INFO on a 1.5.5 config); the pre-runtime phase (CLI flags before any env/file access, the jemalloc purge enable with its two `[warn]` stderr lines, the `busbar-idle-purge` fallback thread) and `BUSBAR_PROFILE`'s 13 named stages verbatim; flags and exit codes as a SUBSET invariant: every 1.5.5 argument behaves identically; `--help` gains lines for the 1.6.0 subcommands (`--data-dir`, `operator keygen`, `keyset import`, `keyset recipient-keygen`, `policy sign`) and those arguments no longer exit 2 — the one additive CLI difference, stated | ops O1/O2/O4, §2.1–2.2 |
| PB-55 | active health probers | `health.mode: none \| dead \| active`, 30 s interval, 5 s timeout, first probe one interval in, recovery and hard-down log lines, `PROBE_ERROR_BODY_CAP` — run as a kernel Tick, verbatim | ops O2, governance G4 |
| PB-56 | egress HTTP client | `redirect: Policy::none()`, `connect_timeout` 10 s, `tcp_keepalive` 60 s, `tcp_nodelay`, HTTP/2 keep-alive and adaptive-window settings, `pool_max_idle_per_host` / `pool_idle_timeout`, `advanced.upstream_http1_only` / `upstream_h2_prior_knowledge` — verbatim | proxy-hooks P3 |
| PB-57 | exclusion point in the pick | `select_weighted_for` filters weight-0, `!lane_admissible` (dead / `BudgetExhausted`) and breaker-open lanes BEFORE the SWRR credit walk; only an at-capacity lane (and the half-open probe race) reaches `try_admit` inside `pick_among` after selection and so consumes an SWRR turn — reproduced exactly | proxy-hooks §2.7 step 6; `store/in_memory/mod.rs:869-900`, `select.rs:417-425` |
| PB-58 | admitted units and money | on every 1.5.5-shaped deployment an ADMITTED `http`/`sse` unit is never ended for money: no `Aborted(Kernel { OverBudget })`, no `Aborted(Kernel { OverdraftCeiling })`; the overdraft ceiling is unbounded (flag-only) on every Migration-sealed bucket; `OverdraftCeiling` and `StaleSlice` are never refusal reasons on a 1.5.5 config; token overshoot is bounded only by the in-flight admitted requests, exactly as at the tag | governance 3.3.5, 3.3.11; proxy-hooks §2.8–2.9 |
| PB-59 | multi-node admission (shared store, no `peers:`) | admission cells are NODE-LOCAL: hydrated once at boot (BOOT-172/173), never re-read; `add_usage` atomic accumulate on the 100 ms flush; a node never sees another node's spend until restart, so a two-node deployment admits up to ≈ N× a cap exactly as 1.5.5; window-roll and `refund_bucket` semantics per the inventory; store slices are ledger-internal and never feed the decision | governance 7.1.2, 7.2.5, 7.4.1, 7.5.1 |
| PB-60 | oversize body | `request_body_max_bytes` is enforced inside the handler AFTER auth and protocol detection (an unauthenticated oversize request gets the 401); rendered dialect-shaped via `proto_for_path` (an oversize request on any `/api` path gets `fallback_error_response`'s envelope, which DISCARDS the status and kind — `404 {"error":{"code":"not_found"}}`, 405 only for `MethodNotAllowed` — on both listeners); the reshape fires only on `AXUM_BODY_LIMIT_413_MARKER`, a relayed upstream 413 passes through untouched: 413, `KIND_REQUEST_TOO_LARGE` / `request_too_large`, "request body exceeds the maximum allowed size", Bedrock `x-amzn-*` headers | routes-admin :99-103, :495-501; dialects :132, :964 |
| PB-61 | chunked bodies | a request body is accepted up to `request_body_max_bytes` (default 32 MiB, ceiling 1 GiB) regardless of chunk count; `MAX_NEEDMORE_FRAMES` never applies to body spooling | config CFG-131 |
| PB-62 | admin scope derivation | `required_scope(method, path)` verbatim: 34 `read-only` / 32 `full` per `x-busbar-required-scope`, incl. `POST /config/validate` and `POST /plugins/inspect` as read-only; a read-only credential succeeds on exactly the 1.5.5 set | routes-admin :266-284, :425-429 |
| PB-63 | plugin reload / rollback mechanics | the governance/store instance is REUSED across `plugins/reload` (keys, budgets, ledger survive); in-flight requests finish on the old snapshot; fail-closed on any pipeline error; ephemeral-mode degrade to report-only reconcile; `kind_restart_default` and the first-party-only `x-busbar-restart-required: false` override; rollback = persist-pin-then-rebuild with `If-Match`, `NO_WRITABLE_OVERLAY_MSG`, the two-stage revert error strings | plugins-stores §2.16–2.17 (:476-478) |
| PB-64 | token-minting egress auth | `jwt-bearer` and `oauth-client-credentials` mint through 1.5.5's background loop verbatim (a Tick-driven, I/O-permitted refresh against the configured `token_url`): `REFRESH_SKEW_SECS = 300`, `MIN_SLEEP_SECS = 30`, `expires_in` default 3600, header built once at mint; before the first mint the request path emits no header (`NoCredential`, the upstream 401 is classified `HardDown`/`Auth`, rendered INGRESS-NATIVE with the body never relayed, and the lane parked (PB-83)) and the active health prober SKIPS the lane (`is_ready()`'s only caller) so a pre-mint lane is never hard-down-parked; the egress-auth kind's purity rule carves out this loop | proxy-hooks :462-470, :509-514, §5.5 (:512; `health.rs:272`) |
| PB-65 | egress auth wire behaviour | the 7 schemes as wire bytes: `api-key` / `x-goog-api-key` header names; the Anthropic five-way key-prefix disambiguation incl. the mode-blind arm emitting BOTH `x-api-key` and `Authorization`; `anthropic-version` always appended; SigV4's SignedHeaders set, double-encoded canonical URI, `us-east-1` fallback, `access:secret[:session]` split; `jwt-bearer` / `oauth-client-credentials` fail closed to `NoCredential`; the header is omitted on an unencodable credential | dialects §8.2; auth-secrets §7 |
| PB-66 | request and response headers | OWNER DECISION: an ALLOW-LISTED client request header rides upstream verbatim, scoped per egress dialect so a beta header sent for one dialect never leaks to a different one on a cross-protocol route or failover — `anthropic-beta` and `anthropic-version` only to a matching `anthropic` upstream, `OpenAI-Beta` only to a matching `openai` or `responses` upstream; every OTHER client request header is dropped, never forwarded; egress headers are otherwise the four-group construction (credential, three-case `content-type`, pinned native-SDK `user-agent`, `accept` with the Bedrock eventstream override) plus the allow-listed set above; on the response `retry-after` is busbar-SET (no dialect parses an upstream `Retry-After`); `content-type` is the upstream's VERBATIM on a same-protocol relay (`engine/mod.rs:2300-2321`) and otherwise the three cases of dialects :1304 — `application/json` for buffered and error responses, `writer.streaming_content_type()` when reframed (SSE, the gemini JSON array, bedrock `application/vnd.amazon.eventstream`), upstream verbatim same-protocol, and the relayed set is PER INGRESS WRITER — `ingress_relayed_response_header_names()`: bedrock `["x-amzn-requestid", "x-amzn-errortype"]` (UUID v4 when absent), anthropic `["request-id"]` (synthesized `req_01<24 base62>` when absent), every other dialect `[]`; everything else stripped; `advanced.response_headers.*` injections per PB-73 are outside this list | dialects §8.1–8.4 (:1305-1316; `proto/mod.rs:695-697`), §6.5 (:997); `engine/egress.rs` `FORWARDED_CLIENT_HEADERS` |
| PB-67 | per-dialect error mapping | the 27-row scenario matrix (:942-970), the per-dialect auth-failure statuses (gemini 400 `invalid_request_error`; bedrock 403 kind `"auth"` with an empty message), the six error-envelope shapes, the kind→native tables, `extract_error`, the in-stream `StatusClass` mapping and the 11 `KIND_*` literals — reproduced verbatim, one cell per row | dialects §6.2–6.6 (:965-975) |
| PB-68 | network guard | precedence: blocked iff `!allow_all` AND on the denylist AND NOT in `allow_overrides`; the hardcoded denylist (`169.254.0.0/16`, `100.100.100.200`, `168.63.129.16`, `192.0.0.192`, `fd00:ec2::254` + six metadata hostnames); `blocked_metadata_hosts` through the same canonicalizer; CIDR rejection; alternate-IPv4 expansion; no runtime DNS check; the `base_url + path` re-check; the public-https / private-http scheme rule with its two error literals | proxy-hooks P4 |
| PB-69 | ingress server posture | ALPN `http/1.1` only (no h2 served); hyper `header_read_timeout` 30 s; `limits.request_body_read_timeout_secs` 30; `tls_handshake_timeout_secs` 10; header size and count limits as hyper's defaults; the 64 KiB cursor / credential budgets never refuse a request 1.5.5 accepted (PB-18) | auth-secrets :2171; routes-admin :511; config :272-273 |
| PB-70 | scrape shape | `/metrics` on a 1.5.5 config exposes NO 1.6.0 series (ledger series live on the ledger endpoints); the pre-registered `.absolute(0)` counters and the `describe_*` absences per PB-53; the `busbar_request_duration_seconds` quantile set is NOT in the repo (exporter defaults; ops UNVERIFIED #1) — Phase −1 scrapes the 1.5.5 binary, records the set here as the resolution of that item, and the oracle diffs it | ops O3 (:1123-1130) |
| PB-71 | documented behaviour | the 27 README (:1047-1073) and 29 CHANGELOG (:1087-1115) claims, the two CONTRADICTED rows (:1061, :1099) each with an explicit cell of the ops cross-check are pinned as code-wins: each row's actual behaviour is the parity target, not the documented one; one §8.1 cell family (`documented-vs-actual`) | ops §8 |
| PB-72 | inventory precedence for bindings | where a binding paraphrases an inventory row, the row (and the code at the tag behind it) wins; a binding found to misread its row is corrected, never the row — the round-3 corrections to PB-1, PB-4, PB-22, PB-26, PB-35, PB-38, PB-39, PB-52, PB-57 are the precedent | 1.5.5-BEHAVIOUR precedence |
| PB-73 | `advanced.response_headers` | `server_timing` / `route_policy` default `false`, RESTART-scoped; `Server-Timing` is a router middleware stamping EVERY response whenever `server_timing: true` (`main.rs:1404-1428`); `x-busbar-route-policy` / `x-busbar-route-target` are emitted only when `route_policy: true` AND a non-default ordering hook (not the SWRR floor registered at `Migration`) produced the order — exactly `proxy/wire.rs:77-112` | config CFG-165/166/167 (:302-304); proxy-hooks §2.12 row 11 |
| PB-74 | reserved-name sets | `RESERVED_POOLS_SECTION_KEYS` (closed), `RESERVED_HOOK_NAMES` (frozen as of 1.5.3), `reserved_admin_name`, `EXPORT_MODULES` — frozen at their 1.5.5 membership; the three new planes add NO reserved word to any 1.5.5-parsed section (the `mcp:` / `a2a:` / `voice:` blocks live under `fleet:`, never top-level — PB-40), so no legal 1.5.5 `config.yaml` becomes a boot failure | config :181-184, :795-800 (BOOT-P07, BOOT-056) |
| PB-75 | served OpenAPI document | `GET /admin/openapi.json` (ADM-052, one of the 66) returns the 1.5.5 blob byte-identical EXCEPT `info.version`: OWNER DECISION — `info.version` reports the running binary's version (`CARGO_PKG_VERSION`, 1.6.0), the same rule `GET /admin/info` (ADM-042) already applies, not a 1.5.5-verbatim pin; every other byte — every path, schema, description and the document's shape — is VERBATIM; the 1.6.0 verbs are described at a new path (`/api/v1/admin/ledger/openapi.json`) — "admin API a superset" means routes, not the legacy document's bytes | routes-admin ADM-052 (:409), :266-284 |
| PB-76 | admin listener route set | the OUTER admin router has exactly its 1.5.5 route set and no fallback (an empty-bodied 404 outside `/api/v1/admin`); UNDER that prefix the nested router's fallbacks apply verbatim — unmatched path ⇒ `404 {"error":{"code":"not_found",…}}`, wrong method ⇒ the `method_not_allowed` envelope (`admin/v1/json/mod.rs:148-149`); `/stats`, `/metrics`, `/metrics/hooks`, `/v1/models` are data-listener verbs only (PB-43) | routes-admin §2 (:93; `build_split_routers_with_limits`) |
| PB-77 | `POST /signing-key/rotate` | report-only exactly as at the tag: rotates nothing, audit action `signing_key.report`, `NothingToRotate` / `NoSigningKey`, the 200 body verbatim; a real 1.6.0 key ceremony lives on a new verb | routes-admin ADM-065 (:422; `M:1713-1760`) |
| PB-78 | `revoke_key` on a tombstoned key | gated on `get_key().is_some()` (not `is_live()`): a tombstoned key returns `200 {"revoked":"<id>"}` and writes a `key.revoke` / `applied` audit row | auth-secrets :618-624 (`admin/mod.rs:1687`) |
| PB-79 | admission refusal identity | the refusal phase order is 1.5.5's: `MissingGroup` first → any FROZEN group in the chain → `concurrent` gauges innermost-first (`retry_after: None`, no `Retry-After`) → windowed buckets in pool-filtered chain order with metric priority `requests` → `tokens` → `budget`; the first blocking bucket names the 429 message and the `Retry-After` scale (Bedrock 400 only for `budget` and `MissingGroup`; `requests`/`tokens` are 429 `rate_limit_error` on every protocol — governance 3.6.3/3.6.5) — one cell per (phase, metric, depth) | governance 3.2.1, 3.2.3–3.2.5, 3.2.7, 3.3.8 (`state.rs:1644-1679`, `:1791-1805`) |
| PB-80 | breaker arithmetic | cooldown `base << streak.min(63)` in u128 clamped to `max_cooldown_secs`; ±10 % jitter with the `[(duration/2).max(1), max_cooldown]` clamp; `honor_retry_after` as a floor up to `max_honored_retry_after_secs`; `hard_down_cooldown_secs`; single-flight half-open probe; the TRIP condition verbatim (`min_requests`, `threshold`, `consecutive_n`, 4.5.23's logical-trip counting, `busbar_breaker_trips_total`) — since PB-4's `Retry-After` and every 503 timing IS this value | governance §4.5 rows 4.5.13–4.5.21 |
| PB-81 | plugin call deadlines | STORES: unset — store calls are synchronous, no `spawn_blocking`, no semaphore, no timeout, the transport deadline advisory only (a slow store is waited out exactly as at the tag); HOOKS: `spawn_blocking` under `MAX_INFLIGHT_HOOK_CALLS = 64` with `call_bounded` at `hooks.<h>.timeout_ms` (default 1 ms; a timed-out gate takes its `on_error` chain, default `nothing`); AUTH: `AUTH_OFFLOAD_MAX_INFLIGHT = 64` / 5 s ⇒ `Denied`, admin chain 16, login 16 ⇒ `Reject` — all fail-closed verdicts verbatim; `PluginTimeout` exists only for 1.6.0-native plugins | plugins-stores :1678, :1715, :1717 |
| PB-82 | usage extraction | 1.5.5's §5.1 read contract is the locator: the cached count is SUBTRACTED from the wire prompt total on openai / responses / gemini (never billed twice); gemini `tokens_out` = `candidatesTokenCount + thoughtsTokenCount`; the forced upstream `stream_options.include_usage` and its two same-protocol hide-back seams (`suppress_same_proto_frame`, `strip_same_proto_usage`) reproduced, so no extra `{choices:[],usage}` chunk reaches an OpenAI client that did not opt in | dialects §4.6 (:706-718), §5 (:780-794) |
| PB-83 | breaker scope | a `BreakerCell` per `(pool, member lane)` with independent Open/Closed per pool; only `max_concurrent`, the lifetime `max_requests`, and the HARD-DOWN park (a 401/402 auth-or-billing failure or a prober failure fans out across the default `""` cell AND every per-pool cell for `hard_down_cooldown_secs`, `availability.rs:521-575`) are lane-global; `busbar_lane_state` and `/stats` per pool | governance 4.5.10 (:421; `store/in_memory/breaker.rs:50-56`) |
| PB-84 | response-stage taps | OWNER DECISION (1.6.0 rebuild, PR-0; amends the prior "pre-forward refusals never tap" text): the `response` stage fires ONCE per request that reaches the forward path (a streaming response taps at response-head time) OR is refused by auth on a hooked pool (401, pre-forward) — that refusal ALSO fires the completion tap once, with the synthetic outcome `rejected_by_auth` and the protocol-native status, so operators see refused requests in their taps; the 1.5.5 binary does the same (oracle cell `hooks\|hooked-pool\|unauth` pins it); every OTHER pre-forward refusal (403/429/413/404) never taps; `outcome ∈ {ok, failed, rejected_by_gate, rejected_by_auth}` is the only synthetic-field set — detached, fire-and-forget, under `MAX_INFLIGHT_TAP_NOTIFICATIONS = 1024` | proxy-hooks §7.2 (`engine/mod.rs:198-221`, `hooks.rs:1407-1417`); `hook_seam_tests.rs completion_tap_fires_synthetic_rejected_by_auth` |
| PB-85 | `max_tokens` injection | on a cross-protocol request into a lane whose dialect `requires_max_tokens()`, `default_max_tokens` is injected ONLY when the IR carries none; a client-supplied value is never clamped or rewritten | dialects §2.6 (:216-240; `ir/variant.rs:88-93`) |
| PB-86 | usage locators are plane-normalized | the four token classes are read through the plane's §5.1 normalization, not a raw pointer (PB-82); the kernel never re-derives a class from the wire | dialects §5.1 |
| PB-87 | non-chat billing classes | `Billing::Flat` (moderation) and the per-op meters for embeddings / image / transcription / speech / rerank are sealed into the migrated card's declared set at `Migration` with 1.5.5's projection, so no class 1.5.5 billed is `Refused(Admit, Unpriced)` and no figure changes | dialects §5.3 (:824-830) |
| PB-88 | dialect pairs never refuse | all 36 ingress×egress pairs are supported with NO pair-level refusal; the 60 bullet-level drop / clamp sites of §3.4 (39 with literal warns) plus the 10 universal `prepare_for_egress` steps of :366-381 (`n > 1 → 1` + warn, reasoning / prompt-cache gates, `cache_control` cap, hosted-tool drop, gemini `thoughtSignature` fill, `extra.clear()` — the mechanism behind the `service_tier` trap) degrade-with-warn exactly as at the tag; a plane may not refuse at the PAIR level; untranslatable CONTENT still renders 1.5.5's 400 `invalid_request_error` "We could not process the content of your request." (dialects :969) | dialects §3 (:342), §3.4 (:407-485) |
| PB-89 | migrated hook `on_error` | `default_on_error() = ON_ERROR_NOTHING`: a failing or timed-out migrated gate does NOT participate (the request is served); natives keep their 1.5.5 timeouts; `on_failure: closed` is for 1.6.0-native hooks only | `config/mod.rs:1796-1799`; proxy-hooks §2.4–2.5 |
| PB-90 | unmapped 1.5.5 config keys | `advanced.response_headers.*` (PB-73), `limits.max_keys_per_principal`, `auth.key_ttl`, `limits.reasoning_effort_budgets.*`, `limits.max_honored_retry_after_secs`, `limits.hard_down_cooldown_secs` (PB-80), `public_url`, `providers_file`, `identity-providers:`, `pools.<p>.affinity.*` (PB-5), `secrets:` — each lands on its 1.5.5 handler unchanged; §10's landing map is complete only with this row | config C1 (the ≈ 12 keys with no other mention) |
| PB-91 | fee basis | the flat fee follows the status of the first frame RELAYED TO THE CLIENT (`finish_inner` reads the client-facing `resp.status()`), so a buffered cross-protocol response whose upstream 2xx becomes a client 502/500 posts `fee_count = 0` (the governance fee refunded; the LANE `max_requests` unit is NOT refunded on the translate-cap arm — `budget_guard.disarm()`, :431 — and is refunded on the other two); the upstream status is internal evidence only | governance 3.8.4 (`ingress/mod.rs:574-579`); proxy-hooks :430-432 |
| PB-92 | `VirtualKey.expires_at` | a stored, UNENFORCED field: the `keys` arm reads only the token `exp` (signature → `exp` → denylist → `by_id` generation); rotate re-mints at 90 d; nothing refuses on `expires_at` | auth-secrets :151-161, :380, :389; 1.5.5-BEHAVIOUR §2 trap |
| PB-93 | 1.6.0-only store ops on an ABI-2 store | the ABI-2 adapter answers every 1.6.0-only operation (`append_batch`, `record_put/get/scan`, `session_*`, `reserve/release`, `heads`, keyset seal) with a NODE-LOCAL in-memory shim (consistent with PB-13: the keyset is ephemeral and unused on such a deployment) — never an error, never a log line, never a boot refusal — so boot and serving on a 1.5.5 sqlite/postgres/mysql/valkey store are byte-identical; the journal on such a deployment is memory-buffered exactly as PB-13 states for `data_dir` unset; durability = the legacy rows' durability, the 1.5.5 rule | plugins-stores §5.8; governance 7.5.3 |
| PB-94 | upstream credential mode | `pools.upstream_credentials` / `pools.<p>.upstream_credentials` (`UpstreamCreds::{Own, Passthrough}`; a pool's scalar REPLACES the section default; BOOT-W04 warning): under `passthrough` the egress-auth unit sends the CALLER's token — `caller_token.unwrap_or("")`, an empty credential for an unauthenticated caller — never the operator key; under `own` the operator key; the client credential masked from the cursor at step 0 is handed to the egress-auth unit as a `SecretSlot` for this purpose only | config CFG-071 (:189), CFG-082 (:203); proxy-hooks §5.1 (:456-458) |
| PB-95 | migrated tap stages | `routing`-stage taps fire inside the egress unit's walk ONCE PER FAILOVER ATTEMPT with 1.5.5's `stage { model, attempt_number (1-based), remaining_candidates, previous_failure }`; `candidate`-stage taps once after gate / base-policy reconcile with `remaining_candidates`; request-stage taps carry no `stage` object; the `hooks/wire.rs` payload byte for byte; `Before(Route)` as a single seat is for 1.6.0-native hooks only | proxy-hooks §2.2 step 16, §2.8 step 4 (`engine/mod.rs:1324-1357`, `:1436-1458`), §7.2 (`hooks/wire.rs:36-65`) |
| PB-96 | streaming byte layout (D2) | the `StreamFraming` vtable verbatim: per-dialect framing and event sequences; bedrock streams `application/vnd.amazon.eventstream` binary frames and gemini without `alt=sse` streams a JSON array (both produced by the `llm` plane's `sse` writer family, declared in §5); the terminal-usage fold / un-fold; the bedrock two-frame split with its exactly-one-`metadata` invariant; the post-stop ordering guard; INV-A open-block drain; multi-citation fan-out; `[DONE]` only for an openai ingress; the anthropic cross-protocol `ping`; a SAME-PROTOCOL response re-emits the original frame bytes (bedrock binary frames never re-encoded — a recomputed CRC is undecodable); the A-tap merges usage PER FIELD, non-zero overrides, anthropic latching `message_start` usage and backfilling the terminal delta; a same-proto non-stream body over the usage-tap cap bills from the buffered prefix (`BILLING_TRUNCATED_TOTAL` +1); the six IR→wire usage WRITE maps (openai re-adds cache into `prompt_tokens`, responses `reasoning_tokens = 0`, bedrock `totalTokens` excludes cache, cohere no `billed_units`, …); the stop-reason matrix incl. lossy rows, `id = None` / `created = now_epoch` synthesis; tool-ID remap `<prefix>bb1<hex>` with per-dialect prefixes, even-length reverse decode, gemini SipHash ids | dialects :283-296, :348-364, :503-539, :553-618, :631-641, :654-729, :813-822; proxy-hooks :317, :438 |
| PB-97 | pristine request bytes | when `head_provably_pristine` the retained request bytes are re-emitted with no DOM re-serialization (hops 2+ re-parse the pristine bytes) — so an unmodified same-dialect request reaches the upstream byte-identical and the SigV4 payload hash is over the same bytes; the `Ir` → `encode_egress()` path is taken only when a rewrite or a cross-protocol translation happened; `strip_router_shim_keys` / `strip_same_protocol_model_shim` and the Claude-on-Vertex shim (remove `model`, inject `anthropic_version: "vertex-2023-10-16"`, clear `extra`) verbatim | proxy-hooks :233-234, :530-535 |
| PB-98 | `error_map` and lane state carry-over | the `error_map` ladder (provider code first, `context_length` suppressed on 5xx, built-ins only on 400/413, HTTP fallback incl. 529 and 408, unrecognized value warned once and ignored) drives condition→disposition; `restore_health_impl` carries lane state across a config apply (`(model, provider)` match, budget `snap.budget.min(new_cap)` only when `limited && >= 0`, `HalfOpen → Open`); the five ranking natives verbatim (`weighted` abstains; `cheapest` / `fastest` / `usage` demote a missing signal to last with `idx` tie-break, all-missing ⇒ abstain; `least_busy` never abstains); a migrated hook receives `wire::build`'s bytes with ops `decide` / `transform` / `notify`, reply precedence `reject > restrict > abstain > order`, a malformed `restrict` ⇒ empty set ⇒ `on_empty`; a tap fires only for callers inside its `groups:` scope (self + ancestors, empty = all); a rewrite with a missing container or non-string content is a silent no-op returning `false`; `pools.hooks:` combines additively with a pool's own `hooks:`, deduped by name, firing once at its section-level position | proxy-hooks :118, :189-200, :363-371, :669-716, :752-767, :797; plugins-stores :1029-1033; config CFG-070 |
| PB-99 | legacy rows, hydrate and erasure | `flush_metering` writes `key_group_at_use: ""`, `pricing_version: ""`, `billable_requests: counts.requests`; hydrate trusts `billable_requests` verbatim (no re-derive); every pre-routing rejection runs `finish_rejected`, so a 401/404/413/429 still increments `busbar_requests_total` and the duration summary at `pool="unresolved"` and fires the request-log webhook; the `logs` record and those two metrics fire ONCE per client request in `finish_inner` — never for Handshake, Tick, nested or `Delivery` units on a 1.5.5 deployment; `delete_key` destroys usage rows and credentials but KEEPS metering rows, `scrub_key` nulls PII on a tombstone, and the legacy `/usage` projection follows those rows (the journal's erasure exemption is a 1.6.0 endpoint matter); reads DEGRADE during a store outage exactly as governance :616-681 (`derived_bucket_usage` errors only for an absent/stale cell, `bucket_model_tokens` empty, the scrape skips affected gauges); the 13 gauges are scrape-time derived under `spawn_blocking`, `idle_timeout` evicts gauges only after 86,400 s, the summary is a rolling `buffer_seconds/3` window, `budget_remaining_cents` only for a capped bucket, `lane_available_permits` only for bounded lanes | governance :559, :616-694; routes-admin :230-233; ops :477-553, :773-798; plugins-stores :976-977, :1175 |
| PB-100 | admin wire details | `with_config_etag` stamps `ETag: "<config_version>"`; `if_match_version` parses `*` / bare / quoted / weak else 400 `MalformedIfMatch`, stale ⇒ 409 `version_conflict` on the ~20 config-plane mutations; every audit action is written at BOTH `applied` and `rejected` with the resource literals (`KEY_RESOURCE_NONE = "key:-"`, `config:settings`, `"process"`); `durable_write_through` / `rebase_nondurable_suffix` gap backfill and `restore_from_store`'s re-verify, `fetch_max` seq floor and seal-on-digest-failure; `VersionLog` `MAX_VERSIONS = 100`, RAM-only, re-seeded at boot (`GET /config/versions` lists only version 0 after a restart — the journal never feeds it); `POST /auth/token` returns `200 {api_key, key_id, group, exp, base_url}` (`base_url` = `public_url` verbatim) and its five refusals in the flat `{"error":"<msg>"}` envelope, with `resolve_exchange` (pools = union across granting bindings, one-key-per-sub upsert, `first_free_self_epoch`); the `GET /auth/token` flow verbatim (constant-time `state`, `id_token` nonce, `MAX_HOPS = 6`, host allowlist and `ssrf_blocked_host`, `FORBIDDEN_HOP_HEADERS`, the `busbar_login` cookie, the exact 400/401/403/502 pages); the data-plane 405 protocol-native envelope, NO CORS layer ever, `OPTIONS` ⇒ `None`, `HEAD` ⇒ `RouteMethod::Get` on plugin routes, `CONNECT`/`TRACE` ⇒ `None`, the six reserved exact paths with their mount-refusal literals, `authorization` never forwarded to a plugin; `/v1/models` picks its envelope by its OWN fingerprint (`anthropic-version`, else gemini path or `x-goog-api-key`, else openai — no `x-api-key` rung); the gemini path-404 family and path-derived `api_version` | routes-admin :124-141, :167, :198-201, :315-320, :590-595, :606, :627-628, :655-683, :714-726; auth-secrets :874-1144 |
| PB-101 | inbound auth details | inbound Bedrock SigV4 verbatim (three-way gate, `chain: []` stays open, pre-buffer structural gate, `UNSIGNED-PAYLOAD` refused, constant-time compare, `DUMMY_SECRET`, the six-row admission matrix); mTLS is required-or-none with no `.allow_unauthenticated()`, the client cert is NEVER mapped to a principal, CN, SAN or fingerprint and has no HTTP status for a rejection — `ClientCertSubject` selectors and the `ClientCert` location are 1.6.0-native only; body-read: `MIN_BODY_THROUGHPUT_BYTES_PER_SEC = 1024`, `BODY_THROUGHPUT_GRACE = 10 s`, the total body deadline `translate_body_max_bytes() / 1024`, the read timeout inter-frame and reset on progress, no ingress whole-request deadline | auth-secrets :167-210, :2205-2214, :2261-2270; routes-admin :510-515 |
| PB-102 | alarms and the disputes report | an alarm and a disputes-report entry are LEDGER-ENDPOINT rows only: no log event, no metric series, no stderr line on a 1.5.5 deployment (ops §5.3's event-field sweep and the closed 25-metric set are byte-identical); the `max_unit_duration` stall alarm on a long stream, the lane-mismatch alarm, the accrual-bound alarm and the `single`-posture mutation alarms all obey this | ops §5.3, O3 |
