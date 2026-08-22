# What's stored WHERE in Busbar

An internal reference for a question that comes up constantly: when Busbar knows
some fact — a signing key, a minted key's scope, a revocation, a budget — *where*
does that fact physically live, and does it survive a restart?

There are four homes. Two of them are declared by the operator and reloaded from
disk on every boot; two of them are runtime state that only persists if a durable
store backs them.

| Home | What it is | Written by | Survives restart? |
|---|---|---|---|
| **config** | The YAML/TOML Busbar parses at boot (providers, pools, IdPs, signing key ref, static identities, policy) | the operator, on disk | **Yes** — reloaded from disk |
| **keyfile / env** | The secret material a config `SecretRef` points at (`file:`, `env:`, …) | the operator / orchestrator | **Yes** — external to Busbar |
| **store** | The governance store: minted-key bindings, denylist, budgets/ledger, sessions/tasks, audit chain | Busbar at runtime | **Only with a durable store** |
| **memory** | The default in-RAM store, plus RAM caches in front of any store | Busbar at runtime | **No** — wiped on restart |

The one-line rule of thumb:

> **config DECLARES how Busbar runs** (providers, pools, IdPs, the signing key,
> static identities, POLICY); **the store RECORDS runtime state** (minted-key
> bindings, the denylist, budgets, sessions/tasks, the audit chain).

Litmus test for "which home?": a minted token is *data* → store. "Users may mint
tokens valid ≤24h" is *policy* → config.

---

## The table

| Thing | Home | Survives a restart on a MEMORY store? |
|---|---|---|
| Signing key (ed25519) | **config** → keyfile/env (`auth.signing_key`) | **Yes** — it is config, not store |
| Static identities (`auth-static-plugin`) | **config** (token → id + roles) | **Yes** — reloaded from disk |
| The minted `vk_` token itself | **never stored** — self-verifying by signature | N/A — shown once |
| Key BINDING (enabled, generation, `allowed_pools`, group, labels) | **store** (RAM-cached) | **No** — lost on restart |
| Denylist / revocation | **store** (+ RAM cache) | **No** — wiped on restart |
| `allowed_pools` scope | **store** (carried on the binding) | **No** |
| Budgets / ledger | **store** | **No** |
| MCP sessions & call log, A2A tasks | **store** (durable), RAM-cached | **No** — reset on restart |
| Audit chain | **store** (tamper-evident) | **No** |

---

## The two-layer insight

The single most useful thing to understand here: verifying a minted key is **two
independent layers**, and they live in different homes.

**Layer 1 — CRYPTO (stateless, backed by config).** The token's signature,
expiry, and audience are checked against the **config** signing key. This layer
holds no runtime state; it is pure math over the token and the key. It therefore
*always* survives a restart, because the signing key is config, reloaded from
disk (`crates/busbar-core/src/governance/state.rs:114`, where `verify_token`
calls `verifier.verify(token, now, expected_aud)`).

**Layer 2 — ADMISSION (stateful, backed by the store).** Even a
cryptographically perfect token is only admitted if:

1. its subject is **not on the denylist**
   (`state.rs:125`), and
2. there is an **enabled binding** whose **generation matches** the token's
   generation claim (`state.rs:136-142`).

Both of those facts are **store** state.

Now the consequence. Busbar's default store is **in-memory** (see below). On a
memory store, a restart wipes the binding. So after a restart:

- Layer 1 still passes — the signature validates, because the signing key came
  back from config.
- Layer 2 fails — there is no binding for the subject any more, so the admit
  check falls through to "subject has no enabled binding" → **401**.

The token is not forged and not expired; it simply has nothing to bind to. That
is the whole reason a minted key "stops working" after a dev restart while a
static-config identity keeps working.

---

## Where each fact is written in the code

- **Signing key resolution** — `crates/busbar-core/src/appbuild.rs:1169`
  resolves `auth.signing_key` (a `SecretRef`) to the ed25519 secret bytes. If it
  is absent there is **no signer** — as of 1.5.1 Busbar does not auto-generate
  one (`appbuild.rs:1165-1168`); config validation has already failed closed if
  the `keys` verifier is in the chain. Fleet deployments provide it shared so
  every node verifies the same tokens.

- **Static identities** — `crates/auth-static-plugin/src/lib.rs`. The config
  supplies `{ token, id, roles }`; a matching token yields `Identify(id, roles)`.
  This is config, reloaded from disk, so it survives a restart independent of any
  store.

- **Minting a key** — `state.rs:253` (`mint_signed`). It persists the policy
  **binding** row via `self.store.put_key(&binding)` (`state.rs:293`) and returns
  a Busbar-signed token that is shown **once**. The token itself is never
  stored — it is self-verifying by its signature.

- **Revocation** — `state.rs` `revoke` path writes the denylist and disables the
  binding: `self.store.add_denylist(sub, reason)` (`state.rs:204`) and then
  `put_key` with `enabled = false` and a bumped generation
  (`state.rs:208-211`). Both are store writes, mirrored into the RAM caches.

- **The memory-store selection & warning** —
  `crates/busbar-core/src/appbuild.rs:1131-1147`. When the configured store is
  the in-memory module, Busbar emits the `GOVERNANCE_STORE_EPHEMERAL` diagnostic
  (defined at `crates/busbar-core/src/diagnostics/mod.rs:2512`): *"Governance
  store is in-memory (ephemeral) — state resets on restart."* A sharper,
  conditional warning also fires when a stateful plane (MCP / A2A) is configured
  on the ephemeral store.

---

## Deployment guidance

Three combinations, and what each one gives you:

- **Memory store + static config keys** → **survives restart.** Identities and
  the signing key are config, reloaded from disk. Good for a fixed set of tokens
  declared by the operator.

- **Memory store + minted keys** → **resets on restart.** Bindings, denylist,
  budgets, and MCP/A2A task state are all store state that a memory store drops.
  This is the dev / ephemeral posture, and Busbar warns about it at boot.

- **Durable store (SQLite / Postgres) + minted keys** → **full-featured and
  persistent.** Minted-key bindings, revocations, budgets, sessions/tasks, and
  the audit chain all survive restarts. This is the posture for anything that
  must retain keys or spend across restarts.

## See also

- [configuration.md](configuration.md) — the config surface (`auth.signing_key`,
  `role_bindings`, `store`).
- [token-exchange.md](token-exchange.md) — how self-serve keys are minted.
- [admin-api.md](admin-api.md) — the revoke / rotate endpoints.
- [internals.md](internals.md) — governance internals.
