# Migrating from 1.5.x to 1.6.0

1.5.3 was the last config-breaking release; the config grammar is frozen and only grows with new
optional keys. 1.6.0 is a **clean-slate** pass that removes the deprecated back-compat surfaces that
1.5.x still accepted — including ones whose deprecation note never committed to a removal window.
Nothing here changes the shape of a config an operator wrote in the 1.5.3 grammar. Every removal
below ships **with a migration path**, so no persisted state and no boot is bricked:

- `busbar --migrate-config old.yaml > config-1.6.yaml` rewrites every retired config-file spelling.
- The persisted config **overlay** (the API-written file that survives a restart) is auto-migrated
  in place at boot the first time 1.6.0 reads it — a pre-1.6.0 overlay never bricks startup.

The recommended path: `busbar --migrate-config old.yaml > config-1.6.yaml`, review any
TODO/WARNING comments, `busbar --validate`, then start. If Busbar boots, you're done.

---

## 1. Hook plugin reference: `plugin:` → `module:`

The retired `plugin:` spelling of a hook's backing-plugin reference is gone. The one wire word for
"which plugin backs this instance" is `module:`, matching `store.module`,
`identity-providers.<n>.module`, and `export.<n>.module`.

**Before (accepted via a read-only alias in 1.5.x):**

<!-- config-check: historical -->
```yaml
hooks:
  audit:
    kind: tap
    plugin: audit-hook
```

**After (1.6.0):**

```yaml
hooks:
  audit:
    kind: tap
    module: audit-hook
```

**Migration.** `busbar --migrate-config` rewrites `plugin:` → `module:` on every hook definition.
A persisted overlay whose hook entries still spell it `plugin:` is auto-migrated to `module:` at
boot (the next overlay write persists the new spelling), so removing the alias never drops an
API-registered hook. This applies to the Admin API write surface too: `POST`/`PUT /api/v1/admin/hooks`
bodies must now name `module:` (a body that sends `plugin:` is rejected as an unknown field).

## 2. Hook stage pinning: `at: <stage>` → `phase: [<stage>]`

The single-stage tap key `at:` is removed; `phase:` (a list, since 1.5.3) is the sole stage-scoping
spelling. An omitted `phase:` still means "the four core stages, and only those" — unchanged.

**Before (1.5.x):**

<!-- config-check: historical -->
```yaml
hooks:
  audit:
    kind: tap
    module: audit-hook
    at: request
```

**After (1.6.0):**

```yaml
hooks:
  audit:
    kind: tap
    module: audit-hook
    phase: [request]
```

**Migration.** `busbar --migrate-config` rewrites `at: <stage>` → `phase: [<stage>]`
(behavior-preserving: a single-stage tap keeps firing at exactly that one stage). A persisted overlay
carrying `at:` is auto-migrated the same way at boot, honoring the same hard stage-value rename the
migrator uses (`route` → `candidate`, `attempt` → `routing`, `completion` → `response`). If an entry
somehow carries both `at:` and a non-empty `phase:`, the `phase:` list wins and the stray `at:` is
dropped — exactly the precedence the old resolver applied.

> The `at:` **value** vocabulary (`route`/`attempt`/`completion`) was already hard-removed in 1.5.3;
> that is unchanged. 1.6.0 removes the `at:` **key** itself.

## 3. `PUT /api/v1/admin/config/settings`: the `persist:` field is removed

The request-scoped `persist:` control key — accepted-then-ignored since durable-by-default landed in
1.5.3 — is gone. The body is now parsed straight into the typed settings shape, whose
`deny_unknown_fields` rejects a stray `persist:`.

**Behavior change to document for clients.** A pre-1.5.3 client that still sends `persist: true`
(or `false`, or any value) now receives a `400 invalid_request` naming `persist` as an unknown
field, instead of the previous silent accept-and-ignore. Drop the field: a mutable config is always
durable and a locked config always refuses, so the field never affected the outcome.

## 4. `GET /api/v1/admin/hooks[/{name}]`: the `at` response field is removed

The hook contract view no longer projects the legacy single-valued `at` stage field. It was `null`
for essentially every hook a running deployment had. Read `fires_at` (the resolved stage set, in
pipeline order) for "when does this hook run", or `phase` for the literal config echo.

## 5. Lane/endpoint status JSON: the `limit` field is removed

The lane status object served by `/stats` no longer carries `limit`, the shorter alias of
`max_concurrent`. Read **`max_concurrent`** — the same integer, unchanged.

**Before:**

```json
{ "model": "...", "max_concurrent": 20, "limit": 20, "inflight": 3, ... }
```

**After:**

```json
{ "model": "...", "max_concurrent": 20, "inflight": 3, ... }
```

---

## 6. MCP tool trust: `refresh_ttl:` → `verify_ttl:` (and verify-on-call)

1.6.0 replaces the background tool-list refresh sweep with **verify-on-call**: an MCP tool server is
re-verified on the `tools/call` path, before the call is dispatched, if its last observation is older
than a per-server staleness bound. The A2A plane's card re-verification moved the same way, on the
delegation path. There is no background job on either plane any more. See
[Tool and agent trust](/docs/tool-and-agent-trust/) for the full model.

The per-server MCP key is renamed and its **meaning changed**:

- `tools.<server>.refresh_ttl:` → `tools.<server>.verify_ttl:`
- It was a background sweep cadence (default `6h`); it is now the longest an observation may be
  **reused on the request path** before a `tools/call` re-verifies (default `5s`). `0` is strict-live.

`busbar --migrate-config` performs the rename and carries your value over **unchanged**, then emits a
loud per-server `WARNING` — because a value that was a sensible sweep cadence is a drift-serving
**window** as a `verify_ttl`. A `refresh_ttl: 6h` becomes a `verify_ttl: 6h`, i.e. a tool whose
fingerprint moved could be dispatched for up to six hours before the next call re-verifies it. Review
every migrated value: a few seconds is the new default, `0` is strict-live, and a large value is an
explicit security downgrade.

The A2A key keeps its name — `agents.<agent>.reverify_ttl:` — and only its default changed from `6h`
to `5s`; nothing in an A2A config file needs editing.

**Before:**

<!-- config-check: historical -->
```yaml
tools:
  servers:
    acme:
      url: https://tools.acme.example/mcp
      pin: { mechanism: cert_spki, key: "sha256/…" }
      refresh_ttl: 6h
```

**After:**

```yaml
tools:
  servers:
    acme:
      url: https://tools.acme.example/mcp
      pin: { mechanism: cert_spki, key: "sha256/…" }
      verify_ttl: 5s   # migrate-config carries 6h over unchanged; reconsider it — see the WARNING
```
