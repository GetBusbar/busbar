# PLUGIN-TREE — the normative plugin-kind spec

**Status: normative.** Where this document and `ARCHITECTURE.md` disagree about a plugin KIND — what
it is, what it declares, what it may depend on, how it registers, what it is named — this document
wins and `ARCHITECTURE.md` is amended to match. Where the contract crates and this document disagree,
the crates win and this document is amended (the precedence rule of `ARCHITECTURE.md`'s preamble,
unchanged). Written to answer, row by row, the plugin-kind design audit of 2026-09-07 against the owner rulings of
the same date, recorded in `ARCHITECTURE.md` Appendix A.

**The rule, in one sentence.** busbar is CORE plus PLUGINS of a closed set of KINDS; every plugin of
every kind integrates with core the same way — it declares data, registers by claim, is sealed by the
root registry, and is driven only by the kernel loop — so that two siblings of one kind are
indistinguishable in shape, and two kinds never fuse in a crate name, a dependency edge, or a
vocabulary.

**The count, and its closure rule.** There are **ten plugin kinds** (§1) — the ninth-plus-one is
**control**, admitted by the owner ruling of 2026-09-08 and walked through §6 as the procedure's
second proof. The tree has **eleven rows**: the last is `unit`, which is CORE — units are the rules,
never loadable, never a plugin — and is listed here only because it obeys the same
declare/register/driven shape and the gate must read its boundary too. An eleventh *plugin* kind may
exist only by walking §6. `loader` and `abi` are not
kinds; they are TCB crates and belong in a `tcb_crates` list, not `[gate.plugin_kinds]`. "Rate card"
is not a kind; it is config with no trait and no crate, and its row leaves the `ARCHITECTURE.md` §1.4
kind table.

---

## 1. The kind table

One line per kind. `Trait` names the single trait in `busbar-contract` that a crate of this kind
implements; implementing a second kind's trait in one crate is a kind fusion and is RED.

| Kind | Crate | Declares (data) | Does (I/O, state) | The ONE trait | May depend on | May be depended on by | Ceiling | Testkit battery |
|---|---|---|---|---|---|---|---|---|
| **plane** | `busbar-plane-<plane>` | `KEY`, `CLAIMS` (own + union of registered dialects'), `OP_CLASSES`, `METER_CLASSES`, `SESSION_FACTS`, `CONTENT_FACTS`, `RECORD_SCHEMAS`, `INTROSPECTION_VERBS`, `INTERRUPT_FACT`, `EGRESS_PACING_FACT`, `CONFIG_SCHEMA`; owns its semantic IR | nothing — pure; state only in `PlaneSessionState` | `plane::Plane` (+ `SessionPlane` iff a claimed transport declares `SESSION`), consts on `PlaneMeta` | contract, grammar, reviewed 3rd-party | kernel, root, its own dialects | none (planes carry no LOC row) | purity · determinism · object-safety · every-refusal-answered · claim-ladder order |
| **dialect** | `busbar-plane-<plane>-<dialect>` | `KEY`, `PLANE`, `CLAIMS`, `LOCATIONS`, `SCHEME_ALT`, `EGRESS_SCHEME`, `STREAMING_CONTENT_TYPE`, `HEAD_KEYS`, `VERBS`, meter-locator pointers | nothing — pure; translates bytes ↔ its plane's IR | `dialect::Dialect` (+ consts on `DialectMeta`) | contract + **its own plane, nothing else** | its own plane's registration only | per-crate LOC row (3.8k–6.3k today) | purity · determinism · object-safety · round-trip byte-exactness · claim-rung uniqueness |
| **control** | `busbar-control-<name>` | `KEY`, `CLAIMS` — its routes, as data — `CONFIG_SCHEMA`, its own request/response bodies, its own UI data | reads node state only through contract traits; changes node state only through the verbs unit; mints credentials only through the auth unit's signer | `control::Control` (+ consts on `ControlMeta`) | contract (+ capabilities if the contract needs it) | kernel, root | none — a control surface is unmetered and carries no metered LOC row | the control battery (claim-table completeness, route uniqueness, unmetered, no-upstream, refusal coverage) |
| **transport** | `busbar-transport-<wire>` | `KEY`, `SELECTOR_FORMS`, `EGRESS_SELECTOR_FORMS`, `COMPOSES_OVER`, `HANDOFF`, `FRAMING`, `SESSION`, `SESSION_BOUND`, `UNIT0_TRIGGER`, `UPGRADES_TO`, `HANDSHAKE_TRIGGER`, `TRANSPORT_FACTS`, `DECODES_PAYLOAD`, `STATUS_CLASS` | sockets, processes, TLS — all of it | `transport::Transport` (+ consts on `TransportMeta`) | contract, contract-transport, **lower transports only** | kernel, root, transports that compose over it | `surface-ceiling:contract-transport` bounds its seam, not the crate | the transport battery (round-trip, half-close, cancel, backpressure, K writers, honest frame meta, composition, handoff, upgrade) |
| **auth** (ingress) | `busbar-auth-<name>` | `KEY`, `LOCATIONS`, `IO: bool`, issuer config | I/O only when `does_io()`, on the blocking pool under a deadline | `kinds::AuthScheme` | contract | kernel | — | universal-config · verify-shape · challenge-rounds · deadline |
| **egress-auth** | `busbar-egress-auth-<name>` | `KEY` | none (pure) | `kinds::EgressAuthScheme` | contract | kernel | — | universal-config · decorate-purity · handshake-round · slot-substitution |
| **store** | `busbar-store-<name>` | `KEY`, `ABI_FLOOR`, `FLEET_SAFE`, schema versions, measured record rate | all durable I/O, blocking pool | `kinds::Store` | contract | kernel | — | `plugin-testkit::store_conformance` (23 assertions) + gap detection + fleet-safe N-node verdict |
| **secret** | `busbar-secret-<name>` | `KEY`, `REF_GRAMMAR` | key I/O | `kinds::Secret` | contract | the auth / egress-auth / transport-key **units** only | — | universal-config · resolve/watch/sign/seal round-trip · canary grep |
| **hook** | `busbar-hook-<name>` | `KEY`, kind (`Tap`\|`Gate`), seats, `HOOK_FACTS`, `on_failure`, `max_priced_delta`, `may_change_destination`, `may_rewrite` | none (pure) | `kinds::Hook` | contract | kernel | — | purity · seat composition · veto/restrict/permutation · priced-delta bound |
| **export** | `busbar-export-<name>` | `KEY`, sink, format, retention | sink I/O | `kinds::Export` | contract | kernel | — | universal-config · at-least-once ack |
| *(core)* **unit** | `busbar-unit-<name>` | nothing plugin-visible; a sealed unit trait | the rules — decides one step | its sealed unit trait in `busbar-contract::unit` | contract, **capabilities** (`busbar-core-capabilities`), contract-transport where it holds a wire handle | kernel only | `busbar-unit-*` ≤ 45k, union ≤ 56k | the step battery + mutation floor on the seven money files |

**The control kind, in one paragraph.** A control surface is an UNMETERED served surface, and the
metering is the whole of the split: a plane is the metered path and a control surface is not on it.
A control crate CAN declare its routes as data (the same claim table a plane declares), own its
request and response bodies, run the control path — verified by the auth kind, admitted, audited,
answered — read node state through contract traits, change node state only through the verbs unit,
mint credentials only through the auth unit's signer, and carry its own UI data. It CANNOT name any
money, fee, rate or posting vocabulary (the `plane-no-money` list, verbatim); reach an upstream (no
egress, pool, routing, failover, breaker or provider vocabulary); appear in a plane's step list or be
called by one (no plane→control edge and no control→plane edge); depend on a transport, plane,
dialect, unit or another control crate; own key material or process-global state; or serve a route
absent from its claim table. `busbar-control-admin` is the first member — `busbar-plane-admin` until
R7 renames it, registered as `control` by an explicit row in `qa/kind-isolation.toml` meanwhile — and
`busbar-control-oauth2` is the second. The AUTH kind is unchanged: the verifier plugins
(`busbar-auth-static`, `busbar-auth-admin-tokens`) stay auth, because a verifier answers a question
about a credential and a control surface serves a route.

**The two workflows, and the one place a wire is registered** (owner refinement, 2026-09-08). A PLANE
follows the strict workflow every plane follows — the ten steps of §2 in order, complete, **never
deviating**: a plane that skips a step or invents one is not a variant of the kind, it is a defect of
it. A CONTROL surface follows the lesser workflow — `verify → admit → audit → answer` — for
system-level functions, and has no other path. **Every kind uses transports**, and no kind of plugin
declares or registers a wire of its own: `http` is declared and registered in exactly ONE spot,
`busbar-transport-http`, and planes and control surfaces reach it only by declaring routes as data
which that transport mounts generically. Three gate rows state this and are owed alongside Appendix
G's six: **plane step-list completeness** (every plane declares and answers the whole step list, no
deviation), **control path only** (a control crate touches no step outside verify/admit/audit/answer),
and **single transport registration** (one registration site per wire; a second declaration of a wire
already declared is RED wherever it appears).

Reading of the table: the ceiling column and the testkit column are part of the kind's definition, not
decoration. **A kind with no ceiling row and no battery is not a kind that can be gated**, and §6
refuses to admit one.

---

## 2. The ONE seam — how every plugin of every kind integrates

Identical for all eleven rows. There is no second path in, and the kernel loop is the only place a
plugin acts.

1. **DECLARE.** The crate exposes one type implementing exactly one kind trait plus the base
   `plugin::Plugin` (`key()`, `kind()`, `abi()`). Every varying thing is an associated const of the
   kind's `*Meta` trait — data, never a callback, never a mount, never a route handler.
2. **CLAIM.** The crate hands the root a registration record: its `Kind`, its `KEY`, its ABI
   generation, and its declarations. A dialect's claim additionally names its `PLANE`; a transport's
   names its `COMPOSES_OVER`; a plane's `CLAIMS` are the union of its own and its registered
   dialects' compile-time claim constants.
3. **SEAL.** The root registry seals the whole set at boot, once: duplicate `KEY` per kind refused;
   ABI below the kind's floor refused; `check_composition` over the transport lattice; claim overlap
   checked ACROSS planes, resolved by the sealed most-specific-wins order, and refused only at equal
   precedence; a claim naming a `SelectorForm` its transport does not declare refused; a
   `SessionPlane` required iff a claimed transport declares `SESSION`. **After the seal no
   registration changes**; a config-derived key is leaked to `&'static str` exactly once, here.
4. **BE DRIVEN.** The kernel loop calls the plugin, never the other way. The ten steps —
   `Arrival · Decode · Authenticate · Verify · Approve · Admit · Route · Meter · Audit · Encode` —
   are the ONLY places a plugin of any kind acts, and each kind is reachable at a fixed subset:

   | Step | Who core calls |
   |---|---|
   | Arrival | transport (`arrival`, `frames`), auth (masked span extraction only) |
   | Decode | plane (`decode_ingress` / `decode_response`) → dialect (translate to the plane's IR) |
   | Authenticate | auth scheme (`verify`, `refresh`), secret (through the auth unit) |
   | Verify | plane (`verify`), transport-key unit → secret |
   | Approve | plane (`approve`), hook at `Before(Approve)` |
   | Admit | hook at `After(Admit)` |
   | Route | plane (`route`, `encode_egress`), hook at `Before(Route)` / `After(Route)`, egress-auth (`decorate`), transport (`dial`, `write`), store (`record_*` on a `PlaneRecord` leg) |
   | Meter | plane (`meter`, `content_facts`) |
   | Audit | plane (`audit`), export (`receive`), store (`append_batch`) |
   | Encode | plane (`encode_response` / `encode_refusal` / `encode_end`) → dialect, transport (`write`) |

5. **NEVER SELF-MOUNT.** No kind's ABI exposes `mount` / `serve` / `bind` / `on_upgrade`. A plugin
   that needs a route DECLARES it; the kernel mounts it from the declared table verbatim.

Consequence, stated so a reviewer can cite it: **there is no seam at which a plugin of kind A reaches
a plugin of kind B.** The single exception in the whole tree is dialect → its own plane, and that
edge exists only to name the plane's IR type.

---

## 3. The uniform crate skeleton

Two siblings of one kind must be indistinguishable in shape. The layout below is required; a file
that is not in it is a finding for the kind-isolation `:shape` row.

```
crates/busbar-<kind>-<name>/
  Cargo.toml            # [dependencies] = exactly the kind's row in §4. Nothing else workspace-local.
  src/lib.rs            # THE SINGLE `pub` ENTRY: one struct + `impl Plugin` + `impl <KindMeta>` +
                        #   `impl <KindTrait>`. Everything else is `pub(crate)`.
  src/meta.rs           # the associated consts — data only, no fn bodies beyond `const fn`
  src/claims.rs         # kinds that claim (plane, dialect, transport): the claim constants
  src/<verb>.rs …       # the kind's own work, one file per declared responsibility
  src/tests/mod.rs      # `#[cfg(test)] mod tests;` from lib.rs — NOT a `tests/` integration dir
  src/tests/conformance.rs   # THE MODULE EVERY SIBLING CARRIES (below)
```

`src/tests/conformance.rs` is the same file, modulo the crate's own type, in every sibling of a kind:

```rust
//! Conformance: this crate is a well-formed <kind>.
#[test] fn kind_is_declared_once()        { assert_eq!(P.kind(), Kind::<K>); }        // and nothing else
#[test] fn abi_matches_the_kind_floor()   { assert_eq!(P.abi(), <K>_ABI); }
#[test] fn key_is_stable_and_lowercase()  { … }
#[test] fn object_safe()                  { let _: &dyn <KindTrait> = &P; }
#[test] fn every_declared_key_resolves()  { … }                    // no stub facts
#[test] fn testkit_battery()              { plugin_testkit::<kind>::battery(&P); }
```

The `plugin-testkit` batteries named in §1's last column are the body of that last test. Today
`plugin-testkit` ships the universal config battery (all kinds) and the store battery; **the other
eight batteries are owed** and are a §8 line item, not a follow-up — a kind whose battery does not
exist cannot be gate-enforced (§6, step 10).

---

## 4. The dependency graph — the compile boundary

This table IS the `:deps` row of `cargo xtask gate kind-isolation`. Read literally: the third column
is the complete allowed set of workspace-local `[dependencies]`; `[dev-dependencies]` are out of
scope, as the manifest allow-list already is.

| From | May name (workspace-local) | May NOT name | Why |
|---|---|---|---|
| dialect | `busbar-core-contract`, **its own** `busbar-plane-<p>` | every other plane, any dialect, any transport, any unit, capabilities, kernel, core, substrate | the plane owns the IR; that is the whole edge |
| plane | `busbar-core-contract`, `busbar-core-grammar` | any transport, any unit, any other plane, **any dialect** (dialects register INTO the plane, never the reverse), capabilities, kernel, core, substrate | a plane names a transport only as a claim constant |
| control | `busbar-core-contract` (+ `busbar-core-capabilities` where the contract needs it) | any transport, any plane, any dialect, any unit, **any other control crate**, kernel, core, substrate | a control surface answers out of node state; the moment it links a wire or a plane it is on the metered path |
| transport | `busbar-core-contract`, `busbar-core-contract-transport`, **lower** `busbar-transport-*` only | any plane, any dialect, any unit, capabilities, kernel | wires compose over wires; `busbar-transport-tls → busbar-unit-transport-key` is the one live breach (§9 row 6) |
| unit *(core)* | `busbar-core-contract`, `busbar-core-capabilities`, `busbar-core-contract-transport` | any plane, dialect, transport, store/auth/secret/hook/export crate | units take facts + principal + clock and nothing else |
| store / auth / egress-auth / secret / hook / export | `busbar-core-contract` (+ the reviewed third-party list) | every other kind's crate, capabilities, kernel, core, substrate, another instance of its own kind | one kind, one crate, no siblings |
| kernel | contract, capabilities, contract-transport, grammar | any plugin crate of any kind | core → plugin, never plugin → core |
| root (`busbar`) | everything | — | naming both axes is the composition root's job |

Two rules that are not edges and must be checked as vocabulary, not manifests:

- **No sibling instance, ever.** No crate of any kind may name another *instance* of any kind — not
  in a dependency, not in a type, not in a string literal, not in a `cfg` feature. The
  `plane-voice` feature pulling `dep:busbar-transport-ws` is one compile switch shared by a plane and
  a transport and is RED under this rule.
- **A plane is dialect-neutral.** A plane crate carries no vendor name, no wire-format reader, no
  per-dialect branch. `busbar-plane-voice/src/twilio.rs` (a named vendor's wire format in a shipping
  plane crate) is the sharpest first red row; `src/ulaw.rs`, `busbar-plane-llm/src/{dialect,claims,codec}.rs`
  and `busbar-plane-{mcp,a2a}/src/jsonrpc.rs` are the rest of the first output.

---

## 5. The declaration model — six declarations, stated kind-agnostically

A plane (through its dialects) DECLARES its wire surface as data; a transport MOUNTS any plane
generically. Six declarations are missing today, and none of the six names a transport or a plane.
Three of them already exist as data in the retiring waist (`ProtocolDecl::{streaming_content_type,
head_keys, verbs}`) and cross into the contract with the dialect kind for free.

| # | Declaration | Shape | Where it lands | Negotiation |
|---|---|---|---|---|
| D1 | request method | `Selector::MethodExact(&'static str)` + `SelectorForm::MethodExact` | `busbar-core-contract::grammar` | a transport that cannot evaluate methods simply omits the form from `SELECTOR_FORMS`; a claim naming it is refused at boot |
| D2 | content type / accept | `Selector::ContentType(&'static str)`; `DialectMeta::STREAMING_CONTENT_TYPE` for the response side | grammar + `DialectMeta` | same boot refusal |
| D3 | streaming kind, declared up front | `PlaneMeta::STREAMING: StreamingKind { Unary, ServerStream, Duplex }` | `PlaneMeta` | a transport whose `FRAMING` cannot hold a stream open refuses the claim at seal |
| D4 | body-pointer routing (the JSON-RPC method name) | `Selector::BodyPointerEquals(ptr, value)` over the closed span grammar | grammar | `SELECTOR_FORMS`; the span scanner already resolves pointers over the scanned prefix |
| D5 | ingress service/method descriptor | `Selector::DescriptorExact { namespace, name }` — a keyed pair, **never** a transport-named arm | grammar | `SELECTOR_FORMS`; the egress twin is the keyed `UpstreamAddress` of D6 |
| D6 | refusal → wire code, as data | `RefusalCodeMap: &[(ReasonCode, WireCode)]` where `WireCode { namespace: &'static str, code: u32 }` | contract; replaces `WireStatus::{Http,Grpc}` and `UpstreamAddress::Grpc`'s named arm | no arm grows per transport; a transport declares its namespace |

Plus one migration that is the same shape: `PlaneRouteSpec`'s three DATA fields (`path`, `method`,
`auth`) move into `busbar-core-contract`; its fourth field, the handler callback, does **not** — a
callback is the plane holding the mount rather than declaring it, which is exactly the shape being
removed.

**The compile-time-claims rule is amended, not broken.** `ARCHITECTURE.md` §3.3's "a claim's selector
is a compile-time constant, never a registration-time value derived from config" stands in intent and
must be restated in letter: *a claim's selector is a compile-time constant of the crate that declares
it; a plane's `CLAIMS` is the union of its own and its registered dialects' compile-time constants.
Union at registration is COMPOSITION, not configuration; there is still no selector form that
resolves a configured string.*

---

## 6. Adding a plugin kind — the only way

A kind is a kernel change and must look like one. Fifteen lines; the dialect kind is walked through
them as the procedure's own first proof.

1. Owner ruling recorded in `ARCHITECTURE.md` Appendix A, dated, naming the kind and why no existing kind holds it.
2. §1.4: one row — closed shape (the kernel's calls) and open vocabulary (what it declares).
3. §3.1: one line in the crate graph. §7: one bullet stating the contract in full, once.
4. `busbar-core-contract`: one `Kind` variant, one sealed marker in `plugin::markers`, one `<KIND>_ABI: AbiVersion`.
5. `busbar-core-contract`: ONE trait, no default bodies, plus its `*Meta` consts trait.
6. Declare its axis: pure or I/O. Pure joins `source-denylist.kinds` and `forbid-unsafe.forbid_kinds`; I/O joins `deny_kinds` and takes a per-kind deadline.
7. One row in §1 of this document, all nine columns filled — including a ceiling and a battery.
8. One row in §4's dependency table, both directions.
9. `qa/construction.toml`: one `[gate.plugin_kinds]` row and one `manifest-allowlist` statement.
10. `plugin-testkit`: one battery. **A kind with no battery may not be gate-enforced.**
11. One `src/tests/conformance.rs` template so siblings are indistinguishable (§3).
12. A registry claim: the boot seal registers it and refuses a duplicate key and a stale ABI.
13. Six `kind-isolation` rows (Appendix G), each with its RED case.
14. One object-safety fixture and one purity/IO meta-test.
15. Every crate has exactly one kind; a kind with zero crates is permitted only with a dated owner
    note saying when its first crate lands, and may not be gate-enforced until then.

---

## 7. Naming, and the rename table

**The rule.** `busbar-<kind>-<name>`. Kind first, always. A dialect's kind segment is `plane-<plane>`
— `busbar-plane-<plane>-<dialect>` — which is the "dialect → own plane only" edge expressed in the
name, so the four-segment form is the same rule, not an exception. **A transport is never named for a
plane: `busbar-transport-<plane-key>` is a finding, ceiling 0.** The kind-isolation gate reads the
kind from segment two, so directory name and `package.name` must agree.

| Old | New | Note |
|---|---|---|
| `busbar-core` | *deleted* | Track R5 |
| `busbar-kernel` | `busbar-core-kernel` | |
| `busbar-caps` | `busbar-core-capabilities` | owner ruling |
| `busbar-contract` | `busbar-core-contract` | |
| `busbar-contract-transport` | `busbar-core-contract-transport` | |
| `busbar-grammar` | `busbar-core-grammar` | |
| `busbar-timing` | `busbar-core-timing` | |
| `busbar-plane-voice` | `busbar-plane-streams` | §9 row 10 |
| `busbar-plane-admin` | `busbar-control-admin` | kind `control`, not `plane`; R7. Registered as control by `qa/kind-isolation.toml`'s `[[registered]]` row until the rename lands, and that row is RED the moment the name says `control` on its own |
| `busbar-llm-codec` | `busbar-plane-llm-{anthropic,openai,gemini,bedrock,responses,cohere}` + residue | kind-last → kind-first; D36/R6 |
| `busbar-mcp-codec` | `busbar-plane-mcp-mcpv2` | |
| `busbar-a2a-codec` | `busbar-plane-a2a-a2a` | |
| `busbar-voice-codec` | `busbar-plane-streams-voice` | |
| `store-memory` | `busbar-store-memory` | dir only; `package.name` already correct |
| `store-example-plugin` | `busbar-store-example` | dir only |
| `auth-static-plugin` | `busbar-auth-static` | dir only |
| `auth-admin-tokens` | `busbar-auth-admin-tokens` | dir only; the token SIGNER moves to `busbar-unit-auth` (owner) |
| `secret-example-plugin` | `busbar-secret-example` | dir only |
| `secret-ref` | `busbar-core-contract` (fold the `SecretRef` type in) | a type crate is not a secret plugin; today the glob makes it one |
| `hook-test-plugin` | `busbar-hook-test` | dir only |
| `hooks-ranking` | `busbar-hook-ranking` | and re-based off `busbar-api` onto `kinds::Hook` |
| `export-example-plugin` | `busbar-export-example` | dir only |
| `plugin-{loader,sdk,sign,pack,testkit}` | `busbar-plugin-{loader,sdk,sign,pack,testkit}` | tooling/TCB, not kinds |
| `plane-abi-spike`, `plane-abi-spike-plugin` | *deleted — DONE* | zero deps in, zero deps out; both crates removed from the tree |
| — | `busbar-egress-auth-{anthropic,openai}` | the kind's first crates (§8) |

Renaming the fifteen directories to their existing `package.name` makes `[gate.plugin_kinds]`'s globs
correct by construction and is the cheap first half of "kind by declaration, not by glob".

---

## 8. Migrating the six kinds with zero contract implementors

Six kinds have rules and gate rows but no crate implementing their `busbar-core-contract` trait; the
live plugins sit on the retiring `busbar-api` ABI. Until these land, the kind gate would police
boundaries around traits nothing implements.

| Kind | Today | Move | Size | Track R |
|---|---|---|---|---|
| store | `store-memory` / `store-example-plugin` impl `busbar_api::Store`; `kinds::Store::record_{put,get,scan}` has ZERO implementors | re-base onto `kinds::Store`; implement the three record verbs; add the kernel-side `Leg::Record` executor | ~150–200 (store) + ~250–350 (kernel executor) | **R5** `store/` row, after D31 B9 |
| hook | `hooks-ranking` impls `busbar_api::RoutingPolicy` | re-base onto `kinds::Hook`; seats from the four-seat table | ~200 | **R5** `hooks/` row |
| auth | `auth-admin-tokens` is a 1.5.5-era module on `busbar-api`; `auth-static-plugin` likewise | re-base onto `kinds::AuthScheme`; the token SIGNER lands in `busbar-unit-auth`, not in a plugin and not in capabilities | ~250 | **R5** `auth/` row |
| secret | `secret-example-plugin` only; `secret-ref` is a type crate swept in by the glob | re-base onto `kinds::Secret`; fold `SecretRef` into the contract | ~150 | **R5** `store/`+`auth/` rows |
| export | `export-example-plugin` on `busbar-api` | re-base onto `kinds::Export` | ~150 | **R5** `export/` row |
| egress-auth | **zero crates**; the schemes are hardcoded in `busbar-unit-egress-auth` and a full dialect-detection ladder sits in `busbar-unit-auth` | create `busbar-egress-auth-anthropic` / `-openai`; the unit keeps the mechanism, the crates keep the vocabulary; `lean-core`'s `max_hits = 21` ratchet closes to 0 | ~300 | **R6**, with the dialect split (same vocabulary, same move) |

Each row also owes its `plugin-testkit` battery (§3) and its `<KIND>_ABI` constant — only `STORE_ABI`
(5) and `TRANSPORT_ABI` (1) exist today, while `Plugin::abi()` is required of every kind.

---

## 9. Answers to the audit — every finding

| Audit | Answer here |
|---|---|
| §1.1 codec is an unnamed kind | Superseded: the kind is **dialect** (§1), named, with a trait, a ceiling, a battery, a naming rule and a manifest rule. The 2026-09-06 "codec folds into its plane" decision is REVERSED by the 2026-09-07 ruling; D36 becomes the split. |
| §1.2 egress-auth has zero crates | §8 last row: two crates, sized, in R6. Until then the kind is doc-only with a dated owner note (§6 step 15). |
| §1.3 six kinds, zero implementors | §8 in full. |
| §1.4 `loader`/`abi` are not kinds | Stated in the header: `tcb_crates`, not `[gate.plugin_kinds]`. |
| §1.5 "plane" defined twice | `gate.plane_crates` (the legacy engines) is deleted with those crates in R3/R5; `[gate.plugin_kinds].plane` is the only definition. |
| §1.6 "Rate card (config)" row | Removed from the kind table; it is config. |
| §1.7 "~10" pinned nowhere | Header: ten plugin kinds (control admitted 2026-09-08), eleven tree rows, closure rule = §6. |
| §1.8 ABI generation for two kinds only | §6 step 4 requires one per kind; §8 owes seven. |
| §2 kind by glob, not declaration | §7 rename makes the globs correct by construction; `:name` (Appendix G) then reads the kind from segment two and cross-checks `Plugin::kind()`. `secret-ref` and the `hooks-ranking` accident both dissolve. |
| §3 contract restated 5–6× | This document is the single statement; `ARCHITECTURE.md` §§1.4/3.2/3.4/6/7 point here as normative. |
| §3 contract-transport names transport instances | D6 (§5): keyed `WireCode` and a keyed extras map; `lean-core`'s scope extends to `busbar-core-contract*`. |
| §3 `unit-transport-key` vs transport, inverted | §4: the edge is deleted; the unit hands the transport an opaque `TransportKeyHandle`. |
| §3 substrate `Transport::{Http, JsonRpc}` | One closed enum spanning both axes is the literal plane-transport shape; `JsonRpc` splits out with the dialect kind. |
| §4 shipping cross-kind references (9 rows) | Rows 1,7 die with the waist; 2,3 move to egress-auth crates (§8); 4 becomes D6's keyed code; 5,6 die with substrate; 8 is the ABI POD and takes D6's namespace; 9 is root-scoped and legitimate. |
| §4 stale `known_red_deps` | Delete: none of the four plane→engine edges exists; planes are clean. Noted for the gate agent. |
| §5 six missing declarations | §5, kind-agnostically, with the boot-refusal negotiation that already exists. |
| §6 transport → unit hard edge | §4; RED under `:deps`. |
| §6 plane ↔ transport compile switch | §4's no-sibling-instance rule; `busbar-transport-ws` takes its own feature. |
| §7 no new-kind rule | §6. |
| §8a dialect contract | §1 row 2; the two existing drafts merge into `DialectMeta` + `Dialect`. |
| §8a compile-time-claims collision | §5's closing paragraph amends the letter, keeps the intent. |
| §8b IR home | Span `Ir` stays in the contract and never grows a semantic one; the semantic IR (2,381 lines) moves to the plane crate — that is what makes §4's dialect row a one-line manifest check. |
| §8c dialect-specific paths in planes | §4's plane-neutrality rule, with the eight rows as its first red output. |
| §8d the llm split, sequenced | §10 Q3 and the migration order: **(a)** oracle boot cell pinning the `DECLS` order (`anthropic, openai, gemini, bedrock, responses, cohere` — operator-visible, every metric-family index is a position in it, silently swapped once already) **BEFORE** any split; **(b)** name the 7,432-line residue's destination — `ir/` → the plane; `proto_codec.rs`/`proto_stream.rs` cannot enter a pure plane crate while they import `http::` and `busbar_substrate_values::breaker::`, so they are cut with those imports or stay in a named residue crate; `chat_handle.rs`/`leaf_codec.rs`/`leaf_handles.rs` are the handle engine; **(c)** then split six directories that already exist. |
| §8e naming | §7, including the four-segment reading. |
| §8f `streams` collision | **Correction to the audit:** `streams:` IS the voice plane's config section today (`crates/busbar-voice/src/config.rs:4-9`, `docs/voice.md:98`) — "the section IS the plane". The `export.<n>.streams` key is a DIFFERENT, 1.5.5-frozen, oracle-pinned field. The rename premise stands; the spec states that **both keys coexist**, the export key never moves, and no rule may treat the two as one vocabulary. |

---

## Appendix G — `cargo xtask gate kind-isolation` (implement verbatim)

Register as `Registration { name: "kind-isolation", batch: 2, tier: Tier::Fast, … }` in
`xtask/src/gates/mod.rs`; copy the shape of `xtask/src/gates/plane_transport_neutrality.rs`. The
seven rows below, plus the three the 2026-09-08 control ruling added (`:plane-steps`,
`:transport-registration`, `:control-path`); `owed()` returns them all, and each has a RED self-test
case planted as an `Overlay`.

| Row | Asserts | RED case (`Expect::Red`) |
|---|---|---|
| `kind-isolation:name` | Every crate under `crates/` has a directory name equal to its `package.name`, matching `busbar-<kind>-<name>` (or `busbar-plane-<p>-<d>` for a dialect, or `busbar-core-*` / `busbar-plugin-*` for core/TCB), and its kind segment equals `Plugin::kind()`. No crate name is `busbar-transport-<plane-key>` for any registered plane key. | Overlay a crate `crates/busbar-transport-mcp/` with `package.name = "busbar-transport-mcp"` → the row names it as a plane-named transport. |
| `kind-isolation:deps` | Each crate's workspace-local `[dependencies]` is a subset of its kind's row in §4. Dialect: exactly `{busbar-core-contract, busbar-plane-<its own plane>}`. Transport: contract + contract-transport + strictly lower transports. No crate names another instance of any kind. `[dev-dependencies]` out of scope. | Overlay `busbar-plane-llm-anthropic/Cargo.toml` with `busbar-plane-mcp` in `[dependencies]` → the row names the edge and the two kinds it fuses. |
| `kind-isolation:vocab` | No plane crate contains a vendor/dialect name or a wire-format identifier (the §1.3 word list ∪ every registered dialect key), comments and `#[cfg(test)]` stripped, word-boundary matched. No kernel/unit crate contains a plane key or dialect name (today's `lean-core`, scope extended to `busbar-core-contract*`). No transport crate names a plane. | Overlay `busbar-plane-mcp/src/vendor.rs` containing `const WIRE: &str = "twilio";` → the row names file, line and word. |
| `kind-isolation:registry` | Every registration record's `Kind` equals the crate's `Plugin::kind()` and its name segment; every kind with at least one crate has a `<KIND>_ABI` constant and every crate's `abi()` meets its kind's floor; no duplicate `(kind, KEY)`; no plugin feature in `crates/busbar/Cargo.toml` pulls a crate of a different kind. | Overlay `crates/busbar/Cargo.toml` with `plane-mcp = ["dep:busbar-transport-grpc"]` → the row names the feature and the two kinds. |
| `kind-isolation:shape` | Every plugin crate has `src/lib.rs` exporting exactly one public plugin type, `src/meta.rs`, and `src/tests/conformance.rs`; it implements exactly one kind trait; no `mount`/`serve`/`bind`/`on_upgrade` symbol on its public surface. | Overlay a plugin crate with a second `impl Store for …` beside its `impl Hook` → the row names the crate and both traits. Second RED: delete `src/tests/conformance.rs` from one sibling → the row names the missing module. |
| `kind-isolation:testkit` | Every kind with ≥ 1 crate has a `plugin-testkit` battery function; every crate of that kind calls it from `src/tests/conformance.rs`. A kind whose battery is absent is reported, not skipped. | Overlay a plugin crate whose `conformance.rs` omits the `testkit_battery` test → the row names the crate and the battery it did not call. |
| `kind-isolation:matrix` | For EVERY kind `K` and EVERY crate `C` under `crates/`, how many times `C` names `K`'s derived vocabulary — `K`'s member package names, their kind-qualified ids, and (for the plane and transport families, the two the kind table itself calls instance vocabularies) their bare ids — in every `.rs` and `.toml` under the crate, WHOLE TEXT: identifiers, string literals, doc comments, ordinary comments, `cfg` attributes, Cargo dependency and feature names, and the file's own path. Tests are NOT excluded. **The composition root is measured too.** Two independent scanners (a segment stream and a raw bounded window); the scored count is the HIGHER, and a cell where they disagree is RED unless a `[[disagreement]]` row records it. Ceilings per `(crate, kind)` in `qa/kind-isolation.toml`'s `[[cell]]` table, exact in both directions — above is a raised coupling, below is stale slack. The `[[edge]]` table carries each kind → kind class's ARCHITECTURE citation, its sentence and the line that deletes it; a cell above zero with no class is an unlisted edge. Ship twin: 0 everywhere, and it does not read the tables. | Overlay `crates/busbar/src/root/voice_serve.rs` with the head of the real file (`keep-streams-3` `dd96a04f3`) → the row names `busbar × plane`, `RAISED`, and the heaviest root files. Second RED: the `[[cell]]` row for `busbar × plane` set to `count = "0"` → the same finding with the hand-wired per-plane files named. Third RED: a ceiling left above its count → `STALE SLACK`. |

Ratchets: `:vocab` and `:deps` carry per-crate ratchet counts seeded from the §9 answer table so the
gate can be turned on RED-free and closed row by row; every other row is `max_hits = 0` from day one.
`:name` also emits the `no-plane-named-transport` finding at ceiling 0.

---

## Appendix Q — open questions for the owner

1. **The `streams` key.** The voice plane's config section is already `streams:`, and
   `export.<n>.streams` is a separate 1.5.5-frozen field. Confirm both keys coexist unchanged (the
   spec assumes yes), or name the namespacing if not.
2. **The 7,432-line shared residue of `busbar-llm-codec`.** `ir/` → the plane. Do
   `proto_codec.rs` + `proto_stream.rs` (the cross-dialect fold, which imports `http::` and
   `busbar_substrate_values::breaker::`) get cut of those imports and move into the plane, or stay as
   a named residue crate of no kind? This is a precondition of the split, not a follow-up.
3. **The `unit` row.** Units are core and never loadable (2026-09-06), yet they obey the same
   declare/register/driven shape and the gate must read their boundary. Confirm the tree is eleven
   rows, ten of them plugin kinds — or rule units fully out of the tree, in which case §1's last row and
   §4's `unit` row are deleted and the gate reads unit boundaries from `lean-core` alone.
