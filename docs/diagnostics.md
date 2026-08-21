# Busbar diagnostics catalog

Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its `diag` field. Find the code below for what it means, whether it needs action, and what to do. This page is generated from the code — do not edit by hand.

Codes are grouped by class (the thousands digit).

## 1xxx — Durability & write-through

<a id="durable-writethrough-below-floor"></a>
### BUSBAR-1001 — Durable audit write-through skipped (seq at or below the recovered floor)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `durable-writethrough-below-floor`

An audit entry's sequence number is at or below the recovered durable floor, so it is already persisted under that seq and the write-through is correctly skipped — the entry is retained in the in-memory ring. A single occurrence at boot is expected after a durable-store restore.

**What to do:** None — self-healing. If it warns repeatedly for DIFFERENT sequence numbers, suspect a second node writing the same durable store (see BUSBAR-1002).

<a id="durable-second-writer-detach"></a>
### BUSBAR-1002 — Durable audit log has another writer — this node detached its durable sink

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-second-writer-detach`

The durable audit store's tail is ahead of what this node last persisted, which can only mean a second busbar is writing the same store. The durable audit log supports exactly ONE writer; two nodes overwrite each other's entries and break the hash chain, which the next boot reports as tampering. This node has detached its durable sink and now audits only to its ephemeral in-memory ring.

**What to do:** Ensure exactly one busbar instance is pointed at this durable audit store. Give the other instance its own store, then restart this node to re-attach a durable sink.

<a id="durable-audit-ring-unreconciled"></a>
### BUSBAR-1003 — Durable audit write-through held — ring not yet reconciled with the durable tail

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-ring-unreconciled`

This process's in-memory audit ring is not yet reconciled with the durable tail (the boot restore did not read or verify it, and a retry read is still failing), so the write-through is held rather than risk overwriting durable history. The entry is retained in the RAM ring and will backfill once the store answers with a verifiable tail.

**What to do:** Check the durable audit store is reachable and returns a verifiable tail. This clears itself once a tail read succeeds (logged as recovery at info level).

<a id="durable-audit-writethrough-failed"></a>
### BUSBAR-1004 — Durable audit write-through failed (entry retained in the in-memory ring)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-writethrough-failed`

Appending an audit entry to the durable store failed — typically a durable-store outage. The entry is retained in the in-memory ring and the state snapshot and will backfill on the next successful write-through, so nothing is lost from the ring.

**What to do:** Investigate the durable audit store outage. No entries are lost from the in-memory ring; they persist once the store recovers and the next mutation backfills them.

<a id="durable-audit-backfill-gap"></a>
### BUSBAR-1005 — Durable audit chain has an unrepairable gap (a seq was pruned before it persisted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-backfill-gap`

A durable-chain sequence number is no longer in the in-memory ring (it was pruned during a store outage longer than the ring bound), so it can never be backfilled in-process. The durable chain therefore has an unrepairable gap at that seq and catch-up stops below the hole. This is real durable-audit data loss for that seq.

**What to do:** Recent entries remain in the in-memory ring, but the DURABLE log has a permanent gap at the named seq. Resolve the store outage that caused it; restore the durable store from a backup if the durable chain's completeness is required for compliance.

<a id="admin-store-operation-failed"></a>
### BUSBAR-1006 — Admin store operation failed (generic 500; store detail logged server-side)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-store-operation-failed`

An admin API CRUD or read operation against the governance/durable store returned an error, so busbar answers the admin request with a generic 500. The store's own error (which may embed SQL fragments or backend paths) is logged server-side only — the HTTP body carries no store internals. The `operation` field names which call failed.

**What to do:** Investigate the durable/governance store's health and reachability for the named operation. A transient store hiccup self-heals on retry; sustained failures mean the store backend is unhealthy and admin mutations/reads cannot complete.

<a id="admin-store-task-join-failed"></a>
### BUSBAR-1007 — Admin store blocking task failed to join (cancelled or panicked)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-store-task-join-failed`

An admin store operation ran on a `spawn_blocking` task that failed to join — the blocking store closure was cancelled or panicked — so busbar maps it to a generic 500 rather than let a JoinError propagate as an unwrap on the request path. The blocking store closures do not panic in normal operation.

**What to do:** Investigate the logged operation and store backend — a panic in a blocking store closure is a bug or a resource failure. Capture the error and file a bug if it recurs; the request was safely failed, not mis-served.

<a id="group-delete-key-read-failed"></a>
### BUSBAR-1008 — Group delete could not read keys to check bindings (admin 500)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `group-delete-key-read-failed`

Deleting a group requires a full key scan to count how many keys are still bound to it, and that store read failed, so busbar answers the admin delete with a generic 500 rather than delete a group with unknown live bindings. No group state was changed.

**What to do:** Investigate the governance store's reachability — the key scan could not complete. Retry the delete once the store is healthy; a transient read error self-heals.

<a id="usage-blocking-task-join-failed"></a>
### BUSBAR-1009 — Admin /usage blocking task failed to join (cancelled or panicked)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `usage-blocking-task-join-failed`

The admin /usage read ran on a `spawn_blocking` task that failed to join (cancelled or panicked), so busbar answers the request with a generic 500. Distinct from a store error returned by the read itself (BUSBAR-1006): here the blocking task did not complete at all.

**What to do:** Investigate the logged context and store backend — a blocking-task panic is a bug or a resource failure. Capture the error and file a bug if it recurs; the request was safely failed.

## 2xxx — Audit chain

<a id="audit-chain-verify-failed"></a>
### BUSBAR-2001 — Durable audit chain failed hash-chain verification at boot (tamper evidence)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `audit-chain-verify-failed`

The persisted durable audit log was read at boot but does NOT verify against its own hash chain, so busbar started with an empty in-memory ring rather than trust a log whose integrity is broken. This is distinct from a store read hiccup (BUSBAR-9001): the bytes were read and the chain does not add up, which is tamper evidence — the durable log was altered out from under busbar, or its store is corrupt.

**What to do:** Treat the durable audit store as compromised until explained: capture it for forensic review before it is overwritten. A verification failure means someone or something rewrote persisted audit history; restore the store from a trusted backup once the cause is understood. The running node audits only to its ephemeral ring until a verifiable durable log is restored.

<a id="a2a-task-chain-verify-failed"></a>
### BUSBAR-2030 — A2A per-task provenance chain failed verification on restore (tamper evidence)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-task-chain-verify-failed`

A persisted A2A task row was read back at boot but its per-task provenance chain does NOT verify against its own hashes, so the task is NOT resumed. This is distinct from a row that merely could not be read (BUSBAR-7024): the bytes were read and the chain does not add up, which is tamper evidence — the durable task state was altered out from under busbar, or its store is corrupt. Emitted once per affected task at boot.

**What to do:** Treat the durable A2A task store as compromised until explained: capture it for forensic review before it is overwritten, and restore it from a trusted backup once the cause is understood. The named task is not resumed; other in-flight tasks continue.

<a id="mcp-calllog-chain-verify-failed"></a>
### BUSBAR-2040 — MCP per-call log failed hash-chain verification on restore (tamper evidence)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-calllog-chain-verify-failed`

The persisted MCP per-call log was read at boot but does NOT verify against its own hash chain, which is tamper evidence — a persisted call record was altered out from under busbar, or its store is corrupt. The records are still restored and the chain resumes from the broken tail, because refusing to restore would let anyone able to write to the store DELETE a caller's history by corrupting one record.

**What to do:** Treat the durable governance store as compromised until explained: capture it for forensic review before it is overwritten, then restore from a trusted backup once the cause is understood.

<a id="plane-task-chain-verify-failed"></a>
### BUSBAR-2041 — A2A per-task provenance chain failed hash-chain verification on restore (tamper)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-task-chain-verify-failed`

A persisted A2A task's provenance events were read at boot but do NOT verify against their own hash chain, which is tamper evidence — the persisted events were altered, or the store is corrupt. The chain is resumed from the broken tail rather than refused, so that corrupting one event cannot silently stop all further provenance for the task.

**What to do:** Treat the durable governance store as compromised until explained: capture it for forensic review before it is overwritten, then restore from a trusted backup once the cause is understood.

<a id="plane-calllog-chain-verify-failed"></a>
### BUSBAR-2042 — MCP per-call records failed hash-chain verification on restore (tamper evidence)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-calllog-chain-verify-failed`

A principal's persisted MCP per-call records were read at boot but do NOT verify against their own hash chain, which is tamper evidence. They are still restored and the chain resumes from the broken tail, because refusing here would convert a detection control into a deletion primitive — anyone able to write to the store could delete a caller's history by corrupting one record.

**What to do:** Treat the durable governance store as compromised until explained: capture it for forensic review before it is overwritten, then restore from a trusted backup once the cause is understood.

## 3xxx — Config

<a id="config-overlay-not-writable"></a>
### BUSBAR-3001 — Config overlay backend is not writable (admin-API config mutations refused)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-overlay-not-writable`

The config overlay backend is NOT writable at boot (typically the config directory is mounted read-only), so busbar starts WITHOUT a durable config overlay: it serves traffic normally, but every admin-API config mutation is refused, because a change that cannot be persisted would silently revert on restart.

**What to do:** If a read-only config is intended, set `config.locked: true` to say so and silence this warning. If you want a mutable config, point `config.overlay.file` at a writable path (mount a writable volume and set e.g. `config.overlay.file: /var/lib/busbar/busbar-overlay.json`).

<a id="config-overlay-probe-leak"></a>
### BUSBAR-3002 — Overlay writability probe file could not be removed (may be left behind)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-overlay-probe-leak`

After creating a temporary probe file to test overlay writability, busbar could not remove it. The probe name is pid-scoped, so a leaked probe is never reclaimed by a later boot and slowly accumulates stray files in the config directory. Minor, but surfaced rather than swallowed.

**What to do:** Remove the leaked probe file(s) from the config directory and investigate why unlink failed there (permissions, a network filesystem without delete-on-close). Overlay writes still work; only the probe cleanup failed.

<a id="config-overlay-corrupt-refuse-write"></a>
### BUSBAR-3003 — Config overlay unreadable/corrupt on apply (refusing to overwrite)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-overlay-corrupt-refuse-write`

An admin apply tried to read-modify-write the config overlay but found the existing overlay present yet unreadable/corrupt, so busbar REFUSED to overwrite it — a blind overwrite would drop the hook AND group deletion tombstones every section carries and could resurrect a deleted item. This apply was NOT persisted.

**What to do:** Fix or remove the corrupt overlay file to restore durability, then re-apply. Until then admin config mutations cannot be persisted (they are refused, not silently lost).

<a id="config-overlay-version-too-new-rmw"></a>
### BUSBAR-3004 — Config overlay written by a newer busbar on apply (refusing to overwrite)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-overlay-version-too-new-rmw`

An admin apply found the config overlay was written by a NEWER busbar than this binary, so busbar REFUSED to overwrite it: this binary cannot represent everything the newer overlay holds, and a write would silently discard whatever it does not understand. This apply was NOT persisted.

**What to do:** Apply config mutations from a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands. This binary serves on the overlay it can read but cannot persist changes to it.

<a id="config-overlay-corrupt-base-only"></a>
### BUSBAR-3005 — Config overlay corrupt at boot (starting on base config.yaml alone)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-overlay-corrupt-base-only`

At boot the config overlay is present but unreadable/corrupt, so busbar fails soft and starts on the base config.yaml ALONE — API-applied hooks (INCLUDING security GATES that enforce admission control), groups, and plugin version pins are NOT restored. Any gate registered only via the admin API is now ABSENT until re-applied. busbar never bricks boot on a corrupt overlay, but it must not disarm those gates silently.

**What to do:** Fix or remove the corrupt overlay file to restore durability, then restart so the API-applied hooks and gates are re-loaded. Until then, re-apply any admin-API gates the deployment depends on, or run on base config.yaml deliberately.

<a id="config-overlay-version-too-new"></a>
### BUSBAR-3006 — Config overlay written by a newer busbar (boot refuses to start)

- **Severity:** fatal
- **Since:** 1.6.0
- **Slug:** `config-overlay-version-too-new`

At boot the config overlay is intact and meaningful but was written by a NEWER busbar than this one. Ignoring it would run without hooks and groups the operator believes are persisted — security gates included — so the boot caller REFUSES to start rather than silently disarm them.

**What to do:** Boot a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands. This is a deliberate boot refusal, not a crash — resolve the version mismatch and restart.

<a id="config-overlay-patch-unparsable"></a>
### BUSBAR-3007 — Config overlay patch does not parse (entry not applied)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-overlay-patch-unparsable`

The config overlay holds a named-map patch that, merged against base config, does not produce a definition this binary can parse (it faces the same typed `deny_unknown_fields` parse config.yaml does). busbar drops the entry WHOLE rather than half-apply it, so that named definition is never applied and sits inert in the overlay.

**What to do:** Edit or remove the offending overlay entry (the log names the section and entry), then reload. The operator's stored data is untouched; the entry is simply not applied until it parses.

<a id="config-antidowngrade-floor-invalid"></a>
### BUSBAR-3008 — plugins.min_versions floor is not valid semver (anti-downgrade disarmed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-antidowngrade-floor-invalid`

A `plugins.min_versions` anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (e.g. a stray leading `v`). It cannot be satisfied, so the floored plugin is refused, and — more subtly — an operator who believes the anti-downgrade control is armed does not get the protection they configured.

**What to do:** Fix or remove the named `plugins.min_versions` entry so the floor is a bare MAJOR.MINOR.PATCH version. Until then that plugin is refused and the anti-downgrade floor for it is effectively disarmed.

<a id="config-firstparty-floor-invalid"></a>
### BUSBAR-3009 — plugins.first_party_floors floor is not valid semver (plugin refused unconditionally)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-firstparty-floor-invalid`

A `plugins.first_party_floors` floor is not a valid MAJOR.MINOR.PATCH version. It cannot be satisfied, and because a first-party floor REPLACES the binary-version floor, the named plugin is refused UNCONDITIONALLY until this is fixed — a stricter failure than an invalid `min_versions` floor.

**What to do:** Fix or remove the named `plugins.first_party_floors` entry so the floor is a bare MAJOR.MINOR.PATCH version. Until then that first-party plugin is refused on every boot.

<a id="config-pool-heterogeneous"></a>
### BUSBAR-3010 — Heterogeneous pool (cross-protocol failover may not preserve all features)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-pool-heterogeneous`

A pool's members span more than one upstream protocol, so cross-protocol failover within the pool translates requests and responses via busbar's internal representation (IR) and may not preserve every provider-specific feature. Advisory: the pool is valid and serves, but mixed protocols carry a fidelity caveat.

**What to do:** None required if intentional. If a feature is being lost across failover, split the pool so each pool is single-protocol, keeping cross-protocol members in a fallback tier rather than the same failover pool.

<a id="config-auth-chain-full-scope"></a>
### BUSBAR-3011 — auth.chain entry grants max_admin_scope: full

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-auth-chain-full-scope`

An auth chain entry sets `max_admin_scope: full`, so every principal identified by that module can hold FULL admin authority — the default ceiling is read-only. A security advisory: a compromised or over-broad identity source behind that module becomes an admin-authority source.

**What to do:** Confirm the named module's chain is trusted end to end and that granting full admin to everyone it identifies is intended. Lower `max_admin_scope` (or scope the module's principals) if full admin is broader than needed.

<a id="config-open-admin-mint"></a>
### BUSBAR-3012 — auth.chain names `keys` with an empty admin_auth (anyone can mint virtual keys)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-open-admin-mint`

The auth chain names the built-in `keys` verifier while `auth.admin_auth` is explicitly empty, so the admin API has no credential gating it — ANYONE can mint virtual keys through it. Acceptable only for local development.

**What to do:** Configure `auth.admin_auth` (an `admin-tokens` entry with a `token:`, or an admin module granting `mint`/`full`) before exposing busbar's admin API to any untrusted network, so key minting is gated by an operator credential.

<a id="config-passthrough-unused-apikey"></a>
### BUSBAR-3013 — passthrough provider has a non-empty api_key that is never forwarded (inert config)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-passthrough-unused-apikey`

A provider is configured with a NON-EMPTY api_key while `upstream_credentials` is `passthrough`, under which the upstream key is the caller's own token (or empty), so the configured api_key is NEVER forwarded — it is inert dead config. A legitimate Bedrock-ingress passthrough provider signs per-request via SigV4 and needs no static key, hence a warning rather than a hard reject.

**What to do:** If you intended static-key gating, use `upstream_credentials: own` (plus an auth chain). Otherwise clear the referenced provider secret so the config reflects that no static key is used on that passthrough provider.

<a id="cli-metadata-blocklist-config-unreadable"></a>
### BUSBAR-3014 — --print-metadata-blocklist printed the built-in denylist only (config unreadable)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `cli-metadata-blocklist-config-unreadable`

`busbar --print-metadata-blocklist` could not parse or env-interpolate config.yaml, so it printed the HARDCODED cloud-metadata denylist ALONE and skipped the operator's `security.blocked_metadata_hosts` additions. The list shown is therefore INCOMPLETE — it omits whatever the config would have added — even though the running gateway (once it boots on a valid config) would enforce the full union.

**What to do:** Run `busbar` (or `busbar --validate`) normally to see the precise parse/interpolation error, fix config.yaml, then re-run the flag to see the full effective denylist. The error itself is not echoed here because it could quote a config value.

<a id="cli-validate-config-invalid"></a>
### BUSBAR-3015 — --validate rejected the config (load, resolve, semantic, or secret-resolution failure)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `cli-validate-config-invalid`

`busbar --validate` ran the exact load → resolve → semantic-validate → strict-secret pipeline boot runs and the config did NOT pass at one of those phases, so it exits non-zero. Because `--validate` mirrors boot, this same config would fail to boot the gateway. The specific phase and offending entries are printed alongside this code.

**What to do:** Fix the reported errors in config.yaml / providers.yaml (a parse/structure error, a cross-reference the resolver rejected, a semantic-validation failure, or an unset required secret) and re-run `--validate` until it reports `ok`.

<a id="cli-list-plugins-config-unreadable"></a>
### BUSBAR-3016 — --list-plugins fell back to the default plugins block (config unreadable)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `cli-list-plugins-config-unreadable`

`busbar --list-plugins` could not read/parse config.yaml, so it inventoried the plugins directory using the DEFAULT `plugins:` block (default dir and trust policy) rather than the deployment's configured one. The inventory shown may not reflect the directory, trust policy, or store selection the running gateway would actually use.

**What to do:** This is informational and best-effort pre-deployment. To inventory against the real config, fix config.yaml so it parses (run `busbar --validate` to see the error) and re-run `--list-plugins`.

<a id="config-settings-overlay-unreadable"></a>
### BUSBAR-3017 — Config-settings read found the overlay unreadable/corrupt (reported no root overrides)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-settings-overlay-unreadable`

A `GET /config/settings` read found the persisted config overlay present but unreadable/corrupt, so it returned an EMPTY set of root overrides. Nothing is mutated, but the response cannot be distinguished from a genuine "no overrides set" — the operator's stored single-value overrides may exist on disk yet be absent from this answer.

**What to do:** Fix or remove the corrupt overlay file to restore durable reads (see BUSBAR-3005 for the boot-time counterpart). Until then this endpoint under-reports the stored root settings.

<a id="config-settings-overlay-version-too-new"></a>
### BUSBAR-3018 — Config-settings read found a newer-busbar overlay (reported no root overrides)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-settings-overlay-version-too-new`

A `GET /config/settings` read found the config overlay was written by a NEWER busbar than this binary, so — rather than misrepresent fields it cannot parse — it returned an EMPTY set of root overrides. The response cannot be distinguished from a genuine "no overrides set", so stored overrides may exist yet be absent from this answer.

**What to do:** Read config settings from a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands (see BUSBAR-3006 for the boot-time counterpart).

<a id="config-settings-read-task-join-failed"></a>
### BUSBAR-3019 — Config-settings overlay read task failed to join (500 rather than a fabricated 200)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `config-settings-read-task-join-failed`

The blocking task that reads the config overlay for `GET /config/settings` failed to join — it panicked, or the runtime is shutting down — so busbar returns 500 rather than a fabricated empty-settings 200 that would misreport "no overrides set" when the read never completed. A panic here is a bug.

**What to do:** Retry the request; a shutdown-race clears on its own. A repeatable failure is a panic in the overlay read path — capture the logged join error and file a bug.

## 4xxx — Auth & identity

<a id="token-exchange-mint-failed"></a>
### BUSBAR-4001 — Token-exchange could not mint a self-serve key

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `token-exchange-mint-failed`

An authenticated, authorized token-exchange request could not be completed because minting the self-serve key failed inside busbar (a keystore write or HMAC/signing fault), so the caller receives a 500. The identity was valid; the failure is on busbar's side, not the client's.

**What to do:** Investigate the keystore / signing subsystem — check disk, permissions, and the key-derivation secret. The condition is rare; capture the logged detail and file a bug if it recurs.

<a id="login-offload-saturated"></a>
### BUSBAR-4002 — Login plugin offload saturated (permit not acquired; login rejected fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `login-offload-saturated`

A login-plugin call could not obtain a blocking-offload permit within the wait window because the offload budget is fully in flight — a login plugin is wedged and not returning. busbar rejects the login fail-closed rather than complete a login it never ran. Warned once on entry to the saturated state; recurrence logs at debug.

**What to do:** Investigate the login plugin (LDAP/AD bind, an OIDC token/userinfo round-trip) — it is blocking past its timeout. Restore or restart it; the saturation clears once calls return within budget.

<a id="login-plugin-panicked"></a>
### BUSBAR-4003 — Login plugin call panicked (login rejected fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `login-plugin-panicked`

A login plugin's blocking call panicked (the offloaded task returned a join error), so busbar rejects the login fail-closed rather than complete a login it never verified. A panicking plugin is a plugin bug.

**What to do:** Fix the login plugin — a panic on the login path is a bug in that plugin. Capture the logged method/op context and the plugin's own logs; logins via that method fail until it is corrected.

<a id="auth-chain-open-relay"></a>
### BUSBAR-4004 — auth.chain is empty (open relay)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `auth-chain-open-relay`

The auth chain was built with no verifiers and no keys-in-chain, so every data-plane request is admitted unauthenticated — an OPEN RELAY. This is acceptable only for local development. Emitted once when the chain is built.

**What to do:** Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing busbar to any untrusted network. An open relay in production forwards anyone's traffic on your upstream credentials.

<a id="auth-offload-saturated"></a>
### BUSBAR-4005 — Auth chain offload saturated (permit not acquired; request denied fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `auth-offload-saturated`

The auth chain could not obtain a blocking-offload permit within the wait window because the offload budget is fully in flight — an auth plugin is wedged and not returning. The chain never ran, so the credential is unverified and busbar denies fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.

**What to do:** Investigate the auth plugin — it is blocking past its timeout and starving the offload budget. Restore or restart it; the saturation clears once chain calls return within budget.

<a id="auth-chain-panicked"></a>
### BUSBAR-4006 — Auth chain panicked (request denied fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `auth-chain-panicked`

The auth chain's blocking task panicked, so busbar denies the request fail-closed rather than admit an unverified credential. A panicking chain is a plugin bug. Warned once on entry to the panicking state; recurrence logs at debug.

**What to do:** Fix the auth plugin — a panic in the chain is a bug in one of its modules. Capture the logged error and the plugin's own logs; requests are denied until it is corrected.

<a id="admin-module-unresolved"></a>
### BUSBAR-4007 — admin_auth names a module with no resolved plugin

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-module-unresolved`

The admin auth chain named a module that has no resolved plugin, and busbar skipped it fail-closed. This is supposed to be impossible after a successful boot — `AdminAuthChain::build` fails closed on any unresolvable name — so reaching it means the admin-module table drifted from the configured chain.

**What to do:** Investigate the admin auth configuration and plugin load state; a named admin module is missing at runtime. Restart busbar so boot re-resolves the chain, and file a bug with the logged module name if it persists.

<a id="admin-offload-saturated"></a>
### BUSBAR-4008 — Admin auth offload saturated (permit not acquired; request denied fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-offload-saturated`

The admin auth chain could not obtain a blocking-offload permit within the wait window because the admin offload budget is fully in flight — an admin auth plugin is wedged and not returning. The chain never ran, so busbar denies fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.

**What to do:** Investigate the admin auth plugin — it is blocking past its timeout. Restore or restart it; admin access is denied until admin-chain calls return within budget.

<a id="admin-chain-stalled"></a>
### BUSBAR-4009 — Admin auth chain did not complete in time (request denied fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-chain-stalled`

The admin auth chain's offloaded task did not complete within its deadline, or it panicked, so busbar denies the admin request fail-closed rather than admit an unverified operator. Warned once on entry to the stalled state; recurrence logs at debug.

**What to do:** Investigate the admin auth plugin — it is slow or crashing on the admin path. Restore or restart it; admin access is denied until the chain completes within its deadline.

<a id="admin-forbidden-suppressed"></a>
### BUSBAR-4010 — Admin request forbidden (audit record suppressed this window)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `admin-forbidden-suppressed`

An admin request was forbidden (insufficient scope for the path), and a durable audit record for it was suppressed because one was already written for this principal in the current rate window. This is a per-request signal of a CLIENT-side authorization failure, not an operator problem, so it is emitted at debug to avoid log spam under a client that keeps retrying a forbidden call.

**What to do:** None — self-heals; the client is being correctly refused. Persistent volume from one principal indicates a misconfigured client or a probe; the durable audit chain already carries the first occurrence per window.

<a id="keys-in-chain-passthrough-conflict"></a>
### BUSBAR-4011 — auth.chain names `keys` alongside upstream_credentials: passthrough

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `keys-in-chain-passthrough-conflict`

The auth chain names the `keys` verifier while `upstream_credentials` is set to `passthrough`. keys-in-chain requires a valid virtual key on every request and supersedes passthrough's accept-and-forward-the-caller-credential intent, so passthrough never takes effect. Warned once at first request.

**What to do:** Resolve the config conflict: use `upstream_credentials: own` (or omit it) alongside `keys`, or drop `keys` from the chain if you genuinely want to forward caller credentials. The two settings are mutually exclusive.

<a id="self-subject-unsafe"></a>
### BUSBAR-4012 — Token-exchange refused an unsafe self-serve subject

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `self-subject-unsafe`

A token-exchange request presented a principal id that is unsafe as a self-serve subject — empty, containing a '/' route separator or a control character, or carrying a reserved `vk_`/`user:`/`group:` prefix — so busbar refused it with a 403. This is a CLIENT-supplied bad value, not an operator problem, so it is emitted at debug to avoid spam from a misbehaving client.

**What to do:** None — self-heals; the client must present a valid subject id. If a legitimate identity is being rejected, its id needs to be reshaped to avoid the reserved prefixes and separators.

<a id="egress-apikey-invalid-bytes"></a>
### BUSBAR-4013 — Egress API key contains invalid header bytes (auth header omitted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `egress-apikey-invalid-bytes`

A configured egress credential (a static `api-key`/`x-goog-api-key`) contains bytes that are invalid in an HTTP header value (typically an ASCII control character), so busbar omits the auth header entirely and the upstream will reject with 401. The credential is misconfigured.

**What to do:** Fix the configured egress credential — remove stray whitespace/control characters (often a trailing newline from how the secret was pasted or injected). Requests to that upstream 401 until the key is a valid header value.

<a id="egress-oauth-token-invalid-bytes"></a>
### BUSBAR-4014 — Minted OAuth token contains invalid header bytes (auth header omitted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `egress-oauth-token-invalid-bytes`

An OAuth token minted for egress contains bytes invalid in an HTTP header value, so busbar omits the `Bearer` auth header and the upstream will reject with 401. Fires on mint (per refresh), not per request, and is near-unreachable for a well-formed token endpoint.

**What to do:** Investigate the OAuth token endpoint — it returned an access token with control or non-ASCII bytes. Requests to that upstream 401 until it mints a header-safe token.

<a id="egress-oauth-empty-token"></a>
### BUSBAR-4015 — OAuth token endpoint returned a 200 with an empty access_token

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `egress-oauth-empty-token`

The upstream OAuth token endpoint answered 200 but with an EMPTY access_token. busbar treats it as a (retryable) mint failure rather than storing it, because an empty token collides with the pre-first-mint sentinel and would wedge the lane permanently. It retries on the refresh cadence.

**What to do:** Investigate the OAuth token endpoint / client-credentials configuration — a 200 with no token usually means a misconfigured client, scope, or audience. Egress to that upstream 401s until a non-empty token is minted.

<a id="egress-oauth-mint-failed"></a>
### BUSBAR-4016 — OAuth token mint (refresh) failed; retrying

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `egress-oauth-mint-failed`

The background OAuth token refresh failed to mint a new token. busbar keeps serving the current token and retries soon; if retries keep failing past expiry, egress requests carry a stale/empty token and the upstream 401s. Fires on the refresh cadence, not per request.

**What to do:** Investigate the OAuth token endpoint — a transient outage self-heals on the next retry; sustained failures mean a credential/endpoint/network problem that will 401 egress once the current token expires.

<a id="trust-sweep-not-attempted"></a>
### BUSBAR-4017 — Scheduled trust sweep could not be attempted (registration not contacted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-sweep-not-attempted`

A scheduled trust sweep could not even be ATTEMPTED for a registration (a local precondition failed before any contact), so the upstream was not contacted and its trust state is unchanged. The registration is not re-verified this tick.

**What to do:** Investigate the logged reason for the named subject — typically a local resource or config problem preventing the sweep from starting. Trust state is preserved, not demoted; resolve the cause so the registration is re-verified on schedule.

<a id="trust-sweep-contact-failed"></a>
### BUSBAR-4018 — Scheduled trust sweep could not authenticate the upstream (failed contact recorded)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-sweep-contact-failed`

A scheduled trust sweep reached the upstream but could not authenticate it, so busbar records a failed contact against the registration. Repeated failed contacts feed the anomaly breaker toward suspension (see BUSBAR-4021).

**What to do:** Investigate the named upstream's reachability and credentials for the logged subject. A transient failure is recorded and self-heals on a later clean sweep; persistent failures will suspend the registration.

<a id="trust-upstream-drifted"></a>
### BUSBAR-4019 — Upstream drifted from the approved pin (registration demoted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-upstream-drifted`

A scheduled trust sweep found the upstream DRIFTED from its approved pin — something changed underneath a standing approval — so busbar demoted the registration and it stops serving until an operator re-approves. This is the headline trust diagnostic: the operator's first notice that a pinned upstream changed.

**What to do:** Review the logged drift (pin change, added/removed/changed attributes) for the named subject. If the change is expected, re-approve the registration to restore service; if not, treat it as a potential compromise of that upstream.

<a id="trust-recovery-held"></a>
### BUSBAR-4020 — Clean trust observation held (recovery backoff not yet elapsed)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `trust-recovery-held`

A scheduled trust sweep made a clean observation, but the recovery backoff since the last drift has not yet elapsed, so the observation is not yet believed and the registration stays demoted for now. This is the expected self-healing backoff, so it is emitted at debug.

**What to do:** None — self-heals. The registration recovers automatically once enough consecutive clean observations accumulate past the recovery backoff.

<a id="trust-registration-suspended"></a>
### BUSBAR-4021 — Anomaly breaker suspended a trust registration

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-registration-suspended`

The trust anomaly breaker suspended a registration — accumulated failed contacts or drift crossed its threshold — so the registration stops serving until the condition clears or an operator intervenes. A transition event, emitted once per suspension.

**What to do:** Investigate the named subject's upstream (see the preceding contact-failure or drift diagnostics for the cause). Resolve the underlying fault; the registration recovers or requires re-approval depending on why it was suspended.

<a id="trust-sweep-panicked"></a>
### BUSBAR-4022 — Scheduled trust sweep panicked (job continues)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-sweep-panicked`

A scheduled trust sweep pass panicked. busbar catches the panic and CONTINUES the sweep job — exiting would turn one bad upstream into a deployment that silently never sweeps again — but that tick's registrations were not all swept. A panicking sweep is a code bug.

**What to do:** Capture the logged plane context and file a bug — a sweep pass should never panic. The job keeps running, but investigate promptly since the panicking tick left some registrations un-swept.

<a id="oauth-as-sweep-failed"></a>
### BUSBAR-4023 — oauth_as expired-record sweep failed (retrying next tick)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `oauth-as-sweep-failed`

The oauth_as authorization-server sweep of expired records failed for a tick — typically a transient store hiccup — so busbar retries on the next tick. Expired records simply linger until a sweep succeeds. Warned once on entry to the failing state; recurrence logs at debug so a persistent store problem cannot spam.

**What to do:** None if it clears on the next tick. Sustained failures indicate an oauth_as store problem worth investigating; expired records accumulate until a sweep succeeds.

<a id="sigv4-hmac-init-failed"></a>
### BUSBAR-4024 — SigV4 HMAC-SHA256 init failed (documented unreachable)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `sigv4-hmac-init-failed`

Initializing HMAC-SHA256 for AWS SigV4 signing failed. This is documented as unreachable — HMAC-SHA256 accepts a key of any length — so reaching it indicates a serious crypto-library inconsistency. busbar returns an empty signature, which the upstream rejects.

**What to do:** Capture the logged error and file a bug; this should not be possible. SigV4-signed egress (e.g. Bedrock) fails to authenticate until it is resolved.

<a id="oauth-as-ephemeral-signing-key"></a>
### BUSBAR-4025 — oauth_as generated an ephemeral ES256 signing key (tokens die on restart)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `oauth-as-ephemeral-signing-key`

The oauth_as authorization server has no `signing_key` configured, so busbar generated an EPHEMERAL ES256 key at boot. Every token this deployment issues is signed with that in-memory key and stops verifying the moment the process restarts, because a new key is generated on the next boot. Acceptable only for a trial or local development.

**What to do:** Set `oauth_as.signing_key` to a durable key reference before relying on issued tokens across restarts. Until then, every restart invalidates all outstanding oauth_as tokens.

<a id="admin-auth-chain-empty"></a>
### BUSBAR-4026 — Admin API admin_auth chain set EMPTY (open, anonymous, full-authority posture)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `admin-auth-chain-empty`

A PUT to `/api/v1/admin/admin-auth` applied an EMPTY admin_auth chain, so the admin API now has NO credential gating it — every admin request is admitted anonymously with full authority. This is the open dev posture; it is a deliberate security-posture change, not a per-request event.

**What to do:** Configure a non-empty `admin_auth` (an `admin-tokens` entry with a `token:`, or an admin module) before exposing the admin API to any untrusted network. Leave it empty only for local development.

<a id="admin-createkey-malformed-body"></a>
### BUSBAR-4027 — create_key request body failed to parse (client 400)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `admin-createkey-malformed-body`

A create_key request body did not parse as valid JSON, so busbar returns a generic 400. The body carries secrets (an AWS secret_access_key, the bearer being minted), so only its byte length is logged, never the raw error or an input fragment. This is a CLIENT-side bad request, not an operator problem, so it is emitted at debug.

**What to do:** None — self-heals; the client must send well-formed JSON. Persistent volume from one caller indicates a broken client worth fixing, but it is not a busbar fault.

<a id="createkey-unknown-pool"></a>
### BUSBAR-4028 — create_key allowed_pools names an unconfigured pool (key still created)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `createkey-unknown-pool`

A create_key request listed an `allowed_pools` entry that names no configured pool — a likely typo. The key is still created (the entry activates if the pool is configured later), so this is a non-fatal advisory. It is a per-request, caller-side signal, so it is emitted at debug.

**What to do:** None required — the key was created. If the pool name was a typo, correct it or configure the named pool so the allowed_pools entry takes effect.

<a id="admin-updatekey-malformed-body"></a>
### BUSBAR-4029 — update_key request body failed to parse (client 400)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `admin-updatekey-malformed-body`

An update_key request body did not parse as valid JSON, so busbar returns a generic 400, logging only the body's byte length (never the raw serde error or an input fragment). Mirror of BUSBAR-4027 for the update path. This is a CLIENT-side bad request, so it is emitted at debug.

**What to do:** None — self-heals; the client must send well-formed JSON. Persistent volume from one caller indicates a broken client worth fixing.

## 5xxx — Proxy & routing

<a id="usage-tap-reassembly-cap-exceeded"></a>
### BUSBAR-5001 — Same-protocol non-stream body exceeded the usage-tap reassembly cap (tail retained)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `usage-tap-reassembly-cap-exceeded`

A same-protocol non-streaming JSON response body grew past the usage-tap reassembly cap, so busbar dropped the oldest bytes and retained only the TAIL (where every dialect's `usage` object sits) to still bill the request. The client receives the body verbatim regardless; only the internal billing copy is truncated.

**What to do:** None — self-heals; the trailing usage object still bills correctly for a recognized dialect. If BILLING_TRUNCATED_TOTAL climbs steadily, some upstream is returning unusually large bodies whose usage may undercount for an unrecognized dialect.

<a id="upstream-midstream-transport-error"></a>
### BUSBAR-5002 — Mid-stream upstream transport error (generic interruption returned to the client)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `upstream-midstream-transport-error`

An upstream transport error occurred AFTER the first byte of a streaming response was already sent to the client. busbar returns a generic, vendor-neutral interruption frame in the client's ingress protocol rather than leaking the raw transport error, and records a compensating breaker transient.

**What to do:** None — self-heals per request; the circuit breaker already tracks the upstream fault. A sustained rate indicates a flaky upstream lane worth investigating via breaker telemetry.

<a id="upstream-prefirstbyte-transport-error"></a>
### BUSBAR-5003 — Pre-first-byte upstream transport error (body stream terminated generically)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `upstream-prefirstbyte-transport-error`

An upstream transport error occurred BEFORE the first byte of a streaming response arrived. busbar terminates the body stream with a generic message, refunds the request budget unit, and records a compensating breaker transient so the failed attempt counts against the lane.

**What to do:** None — self-heals; failover and the breaker handle it. Persistent occurrence on one lane points to an unhealthy upstream endpoint.

<a id="lane-breaker-tripped"></a>
### BUSBAR-5004 — Lane circuit breaker tripped (Closed→Open)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `lane-breaker-tripped`

A circuit breaker for a (pool, lane) transitioned Closed→Open after accumulated failures crossed its threshold, so busbar stops sending traffic to that lane until the breaker's cooldown lets it probe for recovery. Emitted once per logical trip.

**What to do:** Traffic fails over to healthy lanes automatically. If a lane trips repeatedly, investigate that upstream's health, credentials, or rate limits.

<a id="routing-policy-failed-on-error-fallback"></a>
### BUSBAR-5005 — Routing policy failed; on_error fallback applied

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `routing-policy-failed-on-error-fallback`

A routing-policy hook returned an ERROR while deciding a request, so busbar applied the pool's configured `on_error` fallback. A hook binary that is down, crashing, or returning garbage degrades every request in the pool to the fallback. Warned once per fault window; continued failures log at debug.

**What to do:** Fix the routing-policy hook — check that its process is running, reachable, and returning a valid decision. The pool serves via `on_error` until it recovers.

<a id="routing-policy-deadline-exceeded"></a>
### BUSBAR-5006 — Routing policy deadline exceeded; on_error fallback applied

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `routing-policy-deadline-exceeded`

A routing-policy hook did not answer within the seam's hard wall-clock deadline, so busbar applied the pool's `on_error` fallback. A slow hook adds latency to every request in the pool. Warned once per fault window; continued timeouts log at debug.

**What to do:** Investigate why the routing-policy hook is slow (overload, blocking I/O, an undersized deadline). Tune the hook or raise its configured timeout if the latency is legitimate.

<a id="on-error-fallback-answered"></a>
### BUSBAR-5007 — on_error fallback hook answered for the failed gate

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `on-error-fallback-answered`

After a routing gate failed, one of its configured `on_error` fallback hooks answered and decided the request. This is a RECOVERY signal: the fallback chain did its job.

**What to do:** None — informational. The paired gate-failure diagnostic (BUSBAR-5005/5006) names the primary hook to fix.

<a id="on-error-fallback-hook-failed"></a>
### BUSBAR-5008 — on_error fallback hook failed; continuing down the chain

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `on-error-fallback-hook-failed`

An `on_error` fallback hook itself returned an error, so busbar continued down the fallback chain to the next link (or the reserved terminal). The fallback chain meant to cover a broken primary is itself partly broken. Warned once per fault window.

**What to do:** Fix the failing fallback hook. The request is still served by a later chain link or the terminal policy, but the chain has less depth than configured.

<a id="on-error-fallback-deadline-exceeded"></a>
### BUSBAR-5009 — on_error fallback hook deadline exceeded; continuing down the chain

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `on-error-fallback-deadline-exceeded`

An `on_error` fallback hook exceeded its deadline, so busbar continued down the fallback chain. Warned once per fault window; continued timeouts log at debug.

**What to do:** Investigate why the fallback hook is slow, or raise its timeout if the latency is expected. The chain still resolves via a later link or the terminal policy.

<a id="crossproto-nonstream-midtransfer-failed"></a>
### BUSBAR-5010 — Cross-protocol non-stream upstream body failed mid-transfer

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-nonstream-midtransfer-failed`

On a cross-protocol non-streaming route, the upstream body failed mid-transfer, so busbar did not record success or usage, refunded the request budget, records a compensating breaker transient, and returns an ingress-native error.

**What to do:** None — self-heals; the breaker compensates. A sustained rate indicates a flaky upstream lane.

<a id="crossproto-translation-cap-exceeded"></a>
### BUSBAR-5011 — Cross-protocol non-stream success body exceeded the translation cap

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-translation-cap-exceeded`

A cross-protocol non-streaming success body exceeded busbar's translation cap, so it cannot be translated into the client's protocol and the client receives a 500 with no completion. This is busbar's OWN cap, not an upstream fault, so tokens are not charged and the breaker success stands.

**What to do:** None — self-heals per request. If it recurs for legitimate large responses, raise the translated-body cap (`limits`) so those responses translate.

<a id="crossproto-binary-codec-failed"></a>
### BUSBAR-5012 — Cross-protocol binary response failed the egress codec (read_response)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-binary-codec-failed`

A binary/opaque cross-protocol upstream response could not be decoded by the egress codec's `read_response`, so busbar returns an ingress-native 500 rather than leaking the upstream's native body. Often a broken or renamed upstream response field.

**What to do:** None — self-heals per request. If it recurs for one upstream, the provider may have changed its response shape; check for a busbar update covering that dialect.

<a id="crossproto-json-codec-failed"></a>
### BUSBAR-5013 — Cross-protocol JSON response failed the egress codec (read_response_value)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-json-codec-failed`

A JSON 2xx cross-protocol upstream response was rejected by the egress codec's `read_response_value` (e.g. a missing expected field), so busbar returns an ingress-native 500 instead of leaking the upstream body. Same root-cause family as BUSBAR-5012.

**What to do:** None — self-heals per request. Recurrence for one upstream suggests a changed or renamed response field; check for a busbar update.

<a id="crossproto-response-not-translatable-degraded"></a>
### BUSBAR-5014 — Degraded cross-protocol response not translatable (ingress-native error returned)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-response-not-translatable-degraded`

On the degraded path, a cross-protocol upstream response could not be translated into the client's protocol, so busbar returns an ingress-native error rather than leaking the upstream's native wire format to a different-protocol client. This is a deliberate refusal to relay a foreign-format body, not a busbar fault.

**What to do:** None — self-heals per request; returning the native error is the correct, safe behavior.

<a id="crossproto-response-not-translatable"></a>
### BUSBAR-5015 — Cross-protocol response not translatable (ingress-native error returned)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `crossproto-response-not-translatable`

A cross-protocol upstream response could not be translated into the client's protocol, so busbar returns an ingress-native error instead of leaking the upstream's native body to a different-protocol client. This is normal, safe operation — an open-relay refusal — not a fault.

**What to do:** None — self-heals per request; refusing to relay an untranslatable foreign body is the intended behavior.

<a id="rewrite-gate-rejected"></a>
### BUSBAR-5016 — Rewrite gate rejected the request

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `rewrite-gate-rejected`

A rewrite-gate hook rejected the request, so busbar returns the hook's clamped status and sanitized message in the client's native envelope. This is normal policy enforcement, not an error.

**What to do:** None — self-heals per request. The ROUTE_POLICY counters carry the volume; a client seeing rejections should adjust its request to satisfy the policy.

<a id="rewrite-body-materialize-failed"></a>
### BUSBAR-5017 — Materializing the validated request body for the rewrite pass failed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `rewrite-body-materialize-failed`

busbar could not materialize the validated request body into a DOM for the rewrite pass, so it fails CLOSED and rejects the request rather than forwarding it un-rewritten. Unreachable in practice (the bytes already validated), but operator-visible if it ever fires.

**What to do:** Investigate — this indicates a serious internal inconsistency (validated bytes that no longer parse). Capture the request context and file a bug; the request was safely rejected, not mis-forwarded.

<a id="rewrite-reserialize-failed"></a>
### BUSBAR-5018 — Re-serializing a committed rewrite failed (request rejected to protect the invariant)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `rewrite-reserialize-failed`

A committed request rewrite could not be re-serialized into the retained bytes, so busbar rejects the request rather than risk a failover hop forwarding the ORIGINAL un-rewritten body. Protects the rewrite invariant (fail-closed) across failover. Not realistically reachable.

**What to do:** Investigate the rewrite hook and request that triggered it; a rewrite that produces an unserializable body is a bug. The request was safely rejected, never forwarded un-rewritten.

<a id="decision-gate-rejected"></a>
### BUSBAR-5019 — Decision gate rejected the request

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `decision-gate-rejected`

A decision-gate hook rejected the request; busbar returns the gate's clamped status and sanitized message in the client's native envelope. Normal policy enforcement.

**What to do:** None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.

<a id="decision-gate-restrict-weighted-escape"></a>
### BUSBAR-5020 — Decision gate restrict left no eligible lane; on_empty: weighted escape

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `decision-gate-restrict-weighted-escape`

A decision gate's restrict left no eligible lane, and its `on_empty` policy is `weighted`, so busbar skips that restriction and falls back to weighted selection across the full pool. Normal advisory-restrict behavior.

**What to do:** None — self-heals per request. If the restriction should be enforced strictly, set its `on_empty` to reject.

<a id="decision-gate-restrict-reject"></a>
### BUSBAR-5021 — Decision gate restrict left no eligible lane (on_empty: reject)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `decision-gate-restrict-reject`

A decision gate's restrict left no eligible lane and its `on_empty` policy is reject (fail-closed), so busbar rejects the request rather than route to an ineligible lane. This is the correct compliance behavior.

**What to do:** None — self-heals per request; the counters carry the volume. If rejections are unexpected, review the pool membership tags against the restrict's required tags.

<a id="routing-policy-rejected"></a>
### BUSBAR-5022 — Routing policy rejected the request

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `routing-policy-rejected`

A routing-policy hook rejected the request; busbar returns the policy's clamped status and sanitized message in the client's native envelope. Normal policy enforcement.

**What to do:** None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.

<a id="routing-policy-restrict-weighted-escape"></a>
### BUSBAR-5023 — Routing policy restrict left no eligible lane; on_empty: weighted escape

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `routing-policy-restrict-weighted-escape`

A routing policy's restrict left no eligible lane and its `on_empty` is `weighted`, so busbar escapes to full-pool weighted selection. Normal advisory-restrict behavior.

**What to do:** None — self-heals per request. Set `on_empty` to reject if the restriction must be enforced strictly.

<a id="routing-policy-restrict-reject"></a>
### BUSBAR-5024 — Routing policy restrict left no eligible lane (on_empty: reject)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `routing-policy-restrict-reject`

A routing policy's restrict left no eligible lane and its `on_empty` is reject (fail-closed), so busbar rejects the request rather than route to an ineligible upstream. Correct compliance behavior.

**What to do:** None — self-heals per request. If unexpected, review pool membership tags against the restrict's required tags.

<a id="attempt-timeout-failover"></a>
### BUSBAR-5025 — No response headers within the attempt cap; failing over

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `attempt-timeout-failover`

An upstream attempt returned no response headers within its per-attempt time-to-headers cap, so busbar fails over to the next candidate lane. Expected under a slow lane; failover is normal operation.

**What to do:** None — self-heals via failover; telemetry counters carry the volume. If one lane times out constantly, investigate its latency or raise its `attempt_timeout_ms`.

<a id="lane-hard-down"></a>
### BUSBAR-5026 — Lane hard-down (breaker trip)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `lane-hard-down`

A lane's circuit breaker is hard-down (tripped) and this is the FRESH logical trip, so busbar fails over and stops routing to the lane until its cooldown allows a recovery probe. Recurring still-down probes log at debug. Emitted once per logical trip.

**What to do:** Traffic fails over automatically. Investigate the named upstream's health if a lane stays hard-down.

<a id="usage-tap-unknown-protocol"></a>
### BUSBAR-5027 — Usage tap: unknown ingress protocol for a same-protocol 2xx body

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `usage-tap-unknown-protocol`

The usage tap could not recognize the ingress protocol of a same-protocol 2xx body, so it bills 0 tokens for the request. Warned once per (protocol, reason); BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.

**What to do:** None if the protocol is genuinely unmetered. If a metered dialect is billing 0 tokens, the protocol name is unexpected — check the route configuration and for a busbar update covering it.

<a id="usage-tap-bad-json"></a>
### BUSBAR-5028 — Usage tap: failed to parse a same-protocol 2xx body as JSON

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `usage-tap-bad-json`

The usage tap could not parse a same-protocol 2xx body as JSON, so it bills 0 tokens for the request. Warned once per (protocol, reason); the raw body is never logged (it may carry secrets). BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.

**What to do:** None — self-heals per request. Sustained occurrence for one upstream means it is returning non-JSON 2xx bodies busbar cannot meter; investigate that upstream.

<a id="usage-tap-decode-failed"></a>
### BUSBAR-5029 — Usage tap: read_response failed to decode a same-protocol 2xx body

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `usage-tap-decode-failed`

The usage tap's `read_response` could not decode a same-protocol 2xx body into the IR, so it bills 0 tokens for the request. Warned once per (protocol, reason); BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.

**What to do:** None — self-heals per request. If a metered dialect bills 0 tokens repeatedly, the upstream's response shape may have changed; check for a busbar update covering it.

<a id="attempt-timeout-degraded"></a>
### BUSBAR-5030 — No response headers within the attempt cap (degraded path)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `attempt-timeout-degraded`

On the degraded routing path, an upstream attempt returned no response headers within its per-attempt cap, so busbar records a breaker transient and tries the next degraded candidate. Degraded-path sibling of BUSBAR-5025.

**What to do:** None — self-heals via the degraded candidate walk; telemetry counters carry the volume.

<a id="fallback-restrict-no-eligible-lane"></a>
### BUSBAR-5031 — Compliance restrict left no eligible lane in the fallback pool (fail closed)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `fallback-restrict-no-eligible-lane`

A compliance restrict re-applied against a fallback pool left no eligible lane, so busbar fails closed (503) rather than spill to an ineligible upstream. Fail-closed is the correct behavior for a compliance restriction.

**What to do:** None — self-heals per request. If the fallback pool should serve this traffic, ensure its members carry the tags the restrict requires.

<a id="prometheus-recorder-install-failed"></a>
### BUSBAR-5032 — Prometheus recorder install failed; /metrics will be empty

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `prometheus-recorder-install-failed`

The Prometheus metrics recorder failed to install at boot, so the /metrics endpoint will be empty for the life of the process. busbar continues serving proxy traffic, but is blind to metrics.

**What to do:** Investigate the boot error (often a duplicate recorder install or a conflicting exporter). Restart busbar after resolving it; /metrics stays empty until then.

<a id="metrics-maintenance-thread-spawn-failed"></a>
### BUSBAR-5033 — Could not spawn the metrics maintenance thread (observations drain on scrape only)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `metrics-maintenance-thread-spawn-failed`

busbar could not spawn the metrics maintenance (drain) thread at boot, so buffered metric observations now drain only when /metrics is scraped instead of on a timer. Metrics are still correct but may lag between scrapes.

**What to do:** Investigate the thread-spawn failure (typically OS thread/resource exhaustion). Metrics remain available on scrape; restart after resolving the resource limit for timely draining.

<a id="metrics-scrape-list-keys-failed"></a>
### BUSBAR-5034 — Metrics scrape: failed to list virtual keys (per-key gauges skipped)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `metrics-scrape-list-keys-failed`

A /metrics scrape could not list virtual keys from the governance store (a transient store hiccup), so it skips the per-key spend/token gauges for this scrape. Other gauges still refresh.

**What to do:** None — self-heals on the next scrape once the store responds. Sustained failures indicate a governance-store problem worth investigating.

<a id="metrics-key-gauge-limit-exceeded"></a>
### BUSBAR-5035 — Metrics scrape: virtual-key count exceeds the per-key gauge limit (truncating)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `metrics-key-gauge-limit-exceeded`

The number of virtual keys exceeds the per-key gauge limit (`metrics.key_gauge_limit`), so busbar emits gauges for only the first `limit` keys to bound Prometheus cardinality and scrape-path DB load. Some keys have no per-key series. Warned once until the count drops back under the limit.

**What to do:** Raise `metrics.key_gauge_limit` if you need per-key series for all keys and can afford the cardinality, or reduce the number of active virtual keys. Aggregate group gauges are unaffected.

<a id="metrics-scrape-key-usage-read-failed"></a>
### BUSBAR-5036 — Metrics scrape: usage read failed; skipping key

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `metrics-scrape-key-usage-read-failed`

During a /metrics scrape, reading one virtual key's usage from the store failed, so busbar skips that key's gauges for this scrape and continues with the rest. Per-key, per-scrape.

**What to do:** None — self-heals on the next scrape. A high volume across keys points to a governance-store problem.

<a id="metrics-scrape-group-ledger-read-failed"></a>
### BUSBAR-5037 — Metrics scrape: group ledger read failed; skipping bucket

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `metrics-scrape-group-ledger-read-failed`

During a /metrics scrape, reading a group budget bucket's ledger from the store failed, so busbar skips that bucket's gauges for this scrape and continues. Per-bucket, per-scrape.

**What to do:** None — self-heals on the next scrape. Sustained failures indicate a governance-store problem.

<a id="plane-breaker-tripped"></a>
### BUSBAR-5038 — Plane breaker tripped (upstream target failing; dispatches fast-fail)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-breaker-tripped`

A non-LLM plane target's circuit breaker transitioned Closed→Open because the upstream target is failing, so further dispatches fast-fail until the half-open probe recovers it. Names the specific target (every plane target shares one degenerate lane, so without this the operator would not learn WHICH server is down). Emitted once per logical trip, not per failure.

**What to do:** Investigate the named plane target's health (the tool/agent/MCP server it fronts). Traffic to it fast-fails until the breaker's half-open probe finds it healthy again.

<a id="plane-breaker-hard-down"></a>
### BUSBAR-5039 — Plane breaker tripped hard-down (definitive auth/billing failure; sticky cooldown)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-breaker-hard-down`

A non-LLM plane target answered a DEFINITIVE failure (auth/billing), so busbar trips its breaker hard-down: dispatches fast-fail for a sticky cooldown rather than keep retrying a target that will keep rejecting. Emitted per hard-down disposition for the named target.

**What to do:** Fix the named target's credentials or billing/quota with its provider — a hard-down is a definitive rejection, not a transient blip. It recovers via the half-open probe once the underlying auth/billing fault is resolved.

<a id="lane-hard-down-all-cells"></a>
### BUSBAR-5040 — Lane hard-down across all cells (sticky cooldown; recovers via half-open probe)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `lane-hard-down-all-cells`

A lane was recorded hard-down across ALL its per-pool cells at once (the all-cells variant of BUSBAR-5026) — every pool's view of the lane is tripped Open with a sticky cooldown. The lane is RECOVERABLE via the half-open probe (it is not marked dead), so it re-admits once a probe succeeds.

**What to do:** Investigate the named upstream/model lane's health — a hard-down across all cells means a definitive lane-wide fault. Traffic fails over automatically; the lane recovers via the half-open probe once the upstream is healthy.

<a id="breaker-unexpected-state-classify"></a>
### BUSBAR-5041 — Unexpected breaker state on classify (fail-safe: deny admission)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `breaker-unexpected-state-classify`

The breaker classify path read a cell state that is not one of the three valid encodings (Closed/Open/HalfOpen). This is IMPOSSIBLE under the atomic-sentinel invariant, so reaching it means a real invariant break or memory corruption. busbar fails SAFE — treats the cell as never-elapsing Open so admission is denied — rather than panic the dispatching task. Warned once per process; recurrence logs at debug.

**What to do:** Capture the logged state value and file a bug — a breaker cell should never hold an unexpected state. Requests to that cell are safely denied (fail-closed) until it is re-armed; investigate for memory corruption if it persists.

<a id="breaker-unexpected-state-probe"></a>
### BUSBAR-5042 — Unexpected breaker state on probe acquisition (fail-safe: refuse)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `breaker-unexpected-state-probe`

The breaker probe-acquisition path read an unexpected cell state (not Closed/Open/HalfOpen). Impossible under the atomic-sentinel invariant; busbar refuses the probe acquisition (admits nobody) rather than panic the dispatching task. Same invariant-break family as BUSBAR-5041. Warned once per process; recurrence logs at debug.

**What to do:** Capture the logged state value and file a bug. Probe acquisition is safely refused; investigate for memory corruption if it persists.

<a id="breaker-unexpected-state-read"></a>
### BUSBAR-5043 — Unexpected breaker state on state read (reporting Closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `breaker-unexpected-state-read`

A breaker cell state read (a total, side-effect-free projection) found an unexpected encoding. Impossible under the atomic-sentinel invariant; busbar reports the benign Closed default rather than panic, keeping the read total for any encoding. Same family as BUSBAR-5041. Warned once per process; recurrence logs at debug.

**What to do:** Capture the logged state value and file a bug — this read should never see an unexpected state. The projection is safe; investigate for memory corruption if it persists.

<a id="breaker-unexpected-state-record-failure"></a>
### BUSBAR-5044 — Unexpected breaker state in record_failure (no-op)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `breaker-unexpected-state-record-failure`

The breaker failure-recording path read an unexpected cell state (not Closed/Open/HalfOpen). Impossible under the atomic-sentinel invariant; busbar treats it as a no-op (like the already-Open case) rather than panic the task. Same family as BUSBAR-5041. Warned once per process; recurrence logs at debug.

**What to do:** Capture the logged state value and file a bug — a breaker cell should never hold an unexpected state. The failure record is safely dropped; investigate for memory corruption if it persists.

<a id="metadata-protection-disabled"></a>
### BUSBAR-5045 — Cloud-metadata SSRF protection DISABLED (allow_all_metadata is set)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `metadata-protection-disabled`

The deployment set the nuclear `allow_all_metadata` escape hatch, so busbar's cloud-metadata SSRF guard is OFF and EVERY cloud-metadata endpoint (e.g. 169.254.169.254, the GCP/Azure metadata hosts) is reachable through the proxy. That is a security-relevant degradation: a crafted upstream URL or a compromised plugin can reach the instance's credential endpoint. Emitted once at boot.

**What to do:** Remove `allow_all_metadata` unless a specific, understood need requires it. If metadata access is genuinely needed, scope it with `security.blocked_metadata_hosts` instead of disabling the guard wholesale (`--print-metadata-blocklist` shows the effective list).

## 6xxx — Plugins

<a id="plugins-fetch-reload-miss"></a>
### BUSBAR-6001 — plugins.fetch missed on reload (keeping the current artifact)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plugins-fetch-reload-miss`

During a reload, fetching a pinned plugin artifact missed (the source did not return a usable download for the pinned spec), so busbar kept the artifact already on disk and continued the reload. The running plugin is unchanged; the intended refresh did not land.

**What to do:** Check the plugin source (registry/URL) and the pinned spec for the named artifact — a transient fetch miss self-heals on the next reload, a persistent one means the pin no longer resolves. busbar keeps serving the current artifact until a fetch succeeds.

<a id="plugin-skipped-trust-policy"></a>
### BUSBAR-6002 — Plugin present but NOT loaded (skipped by trust policy)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plugin-skipped-trust-policy`

A plugin artifact is present in the plugins directory but was NOT loaded because the configured trust policy skipped it (unsigned, an untrusted publisher, or a failed signature/floor check). busbar fails closed: an untrusted plugin is left inert rather than loaded. Emitted once per skipped plugin at boot.

**What to do:** If the plugin should load, sign it with a trusted publisher key or add that publisher to `plugins.trust` (the log names the plugin, file, and reason). If the skip is intended, remove the artifact from the directory to silence the notice.

<a id="plugin-loaded-unverified"></a>
### BUSBAR-6003 — Plugin loaded UNVERIFIED (permitted by an explicit plugins.trust opt-in)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plugin-loaded-unverified`

A plugin was loaded even though its signature is UNVERIFIED — its code is running unauthenticated, permitted only because an explicit `plugins.trust` opt-in (`allow_unsigned`/`allow_third_party`) let it through. Security-relevant: unverified plugin code runs in-process with busbar's privileges. Emitted once per such plugin at boot.

**What to do:** Prefer a signed artifact from a trusted publisher and remove the `plugins.trust` opt-in once you no longer need it. If running unverified is a deliberate, understood choice (e.g. a locally-built plugin), the opt-in is what keeps it explicit.

<a id="plugins-dir-fingerprint-failed"></a>
### BUSBAR-6004 — Cannot fingerprint the plugins dir (bypassing the catalog cache)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `plugins-dir-fingerprint-failed`

A real I/O error (not a missing directory) meant the plugins directory could not be fingerprinted, so its content-hash freshness signal cannot be trusted and busbar bypasses the catalog cache for this read, falling through to the real scan. Self-healing: it clears once the directory is readable. Warned once on entry to the failing state; recurrence logs at debug.

**What to do:** Investigate the plugins directory's readability (permissions, a stale/hung mount). The catalog read still works via the direct scan; the cache re-engages once the directory fingerprints cleanly again.

<a id="plugin-catalog-scan-gate-timeout"></a>
### BUSBAR-6005 — Plugin catalog scan gate not acquired within the wait bound (retryable 503)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plugin-catalog-scan-gate-timeout`

A plugin catalog scan could not acquire the scan gate within its bounded wait, which signals a PRIOR scan is not returning — typically a stale or hung plugins_dir mount. busbar answers with a retryable Unavailable (503) rather than hang this request behind the wedged scan.

**What to do:** Investigate the plugins_dir mount — a hung scan usually means the directory's filesystem is stalled (e.g. an unresponsive network mount). Resolve the mount; the gate frees once the prior scan returns or is unwedged.

<a id="plugin-catalog-blocking-task-failed"></a>
### BUSBAR-6006 — Plugin catalog blocking task failed to join (fail-soft to the compiled-in row)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plugin-catalog-blocking-task-failed`

The plugin catalog store scan ran on a `spawn_blocking` task that failed to join (cancelled or panicked). busbar fails SOFT to the always-true compiled-in catalog row rather than a 500 — this is just a plugin CATALOG read — the same posture it takes on an unparseable plugins_cfg. Rare.

**What to do:** Investigate the logged context if it recurs — a blocking-task join failure on the catalog read is unusual. The catalog is served fail-soft in the meantime, so the admin read still returns.

<a id="plugin-rollback-pin-persist-failed"></a>
### BUSBAR-6007 — Plugin rollback could not persist the version pin (nothing swapped, fail-closed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plugin-rollback-pin-persist-failed`

A plugin rollback tried to persist the lowered version pin to the config overlay and the write failed, so busbar FAILS CLOSED and swaps nothing — the running engine still serves the current plugin. Persisting the pin is the whole point of the rollback: a swallowed failure would swap the live engine while disk still carried the rolled-forward state, so a restart would silently re-upgrade.

**What to do:** Investigate the config overlay's writability (the log names the plugin). Fix the overlay path/permissions and re-issue the rollback; nothing was changed, so it is safe to retry.

<a id="plugin-rollback-revert-failed"></a>
### BUSBAR-6008 — Plugin rollback rebuild failed AND reverting the version pin failed (disk out of sync)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plugin-rollback-revert-failed`

A plugin rollback's rebuild failed AFTER the lowered pin was persisted, and the compensating revert of that pin ALSO failed, so disk now carries the rolled-forward pin while the running engine still serves the prior plugin. A restart would honor the stale on-disk pin and contradict the running engine. Loud because disk and the live engine now disagree.

**What to do:** Fix the config overlay so the version pin matches the plugin the running engine serves BEFORE restarting (the log names the plugin and both errors). Until then a restart would come up in a state the running engine rejected.

<a id="cli-validate-plugin-preflight-failed"></a>
### BUSBAR-6009 — --validate plugin pre-flight failed (structure, trust, conflict, or store resolution)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `cli-validate-plugin-preflight-failed`

`busbar --validate` ran the same plugin pre-flight boot runs — consistency, trust-policy resolution, the three-phase scan of every tarball (structural → trust → conflict), and store resolution — and it FAILED. Because this is the boot pipeline (manifest-only, no dlopen), the same plugin set would fail the plugin half of boot.

**What to do:** Fix the reported plugin problem: a malformed manifest, a signature/trust-policy rejection, an ABI-floor or version-floor violation, a name/alias conflict, or an unresolvable `store.module`. Re-run `--validate` until it reports `ok`.

<a id="cli-list-plugins-trust-invalid"></a>
### BUSBAR-6010 — --list-plugins could not build a trust policy (plugins.trust is invalid)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `cli-list-plugins-trust-invalid`

`busbar --list-plugins` could not compile a trust policy from the `plugins.trust` block (e.g. an unparsable trust anchor or a malformed policy), so it cannot compute per-tarball signature verdicts and exits non-zero. The running gateway would reject this same `plugins.trust` at boot.

**What to do:** Fix the `plugins.trust` block (the logged error names the problem), then re-run `--list-plugins` or `--validate`.

## 7xxx — Plane protocols

<a id="a2a-extended-card-agent-omitted"></a>
### BUSBAR-7001 — Agent omitted from the extended agent card (card names the backend authority in text)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-extended-card-agent-omitted`

While building the extended agent card, one member agent was omitted because its own card names the backend authority in free text that busbar cannot safely rewrite. Publishing it unchanged would leak the backend endpoint, so the agent is dropped from the extended card rather than exposed. A transcode limitation, not an outage.

**What to do:** None — self-heals. If the omitted agent should be reachable, adjust its published card so it does not name the backend authority in unstructured text busbar cannot rewrite.

<a id="a2a-push-config-unrecorded"></a>
### BUSBAR-7002 — A2A push-notification config could not be recorded (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-push-config-unrecorded`

A caller registered a push-notification callback but the pinned config could not be written to the durable task store, so the request is refused rather than accepting a callback busbar cannot persist. Typically a durable-store outage. Warned once on the transition into the failing state; subsequent failures hold at debug to avoid spam.

**What to do:** Investigate the durable governance/task store outage. Push-config registration resumes once the store accepts writes again.

<a id="a2a-pool-not-interchangeable"></a>
### BUSBAR-7003 — A2A submission not accepted (the pool's members are not interchangeable)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-pool-not-interchangeable`

A submission targeted an agent pool whose members are not interchangeable under the seam's rules, so it was not accepted. A routine per-request routing refusal, benign and expected under the configured pool policy; surfaced at debug so a busy caller cannot spam the log.

**What to do:** None — self-heals. If submissions should route, configure the pool's members to be interchangeable (matching capabilities) so the seam can dispatch across them.

<a id="a2a-pin-refusal-unrecorded"></a>
### BUSBAR-7004 — Pin-refused A2A task could not be recorded as rejected (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-pin-refusal-unrecorded`

A submission was refused because the pool's members are not interchangeable, but the resulting `rejected` transition could not be written to the durable task store. The caller is still told; the durable row is what could not be updated. Typically a store outage. Warned once on the transition; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. The caller received the refusal; only the durable record of it failed and resumes once the store accepts writes.

<a id="a2a-extended-card-build-failed"></a>
### BUSBAR-7005 — Extended agent card could not be built

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-extended-card-build-failed`

busbar could not build the extended agent card for a request. The card that composes the registered agents into the surface busbar publishes failed to assemble, so the caller is served without the extended view. Usually a registration/config problem in one of the member cards.

**What to do:** Check the registered agent cards named nearby for a malformed or unreachable entry; the extended card composes them, and one bad member fails the build.

<a id="a2a-no-csprng-callback"></a>
### BUSBAR-7006 — No CSPRNG available — busbar registers no push callback of its own with any backend

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-no-csprng-callback`

At startup no cryptographically-secure RNG was available, so busbar cannot mint the unguessable token that secures its own push callback and therefore registers NO callback of its own with any backend. A genuine platform/wiring problem, not a per-request condition — busbar's own push path is disabled for the process lifetime.

**What to do:** Investigate why the platform CSPRNG is unavailable (a broken entropy source or a sandboxed getrandom). busbar's own push registration stays disabled until restarted on a host with a working CSPRNG.

<a id="a2a-pushback-not-delivered"></a>
### BUSBAR-7007 — A2A pushed state was not delivered onward

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-pushback-not-delivered`

A state pushed to busbar by a backend could not be delivered onward to the caller's registered callback (the callback is down or refused it). The task's state is still recorded and the caller's poll will find it; the push is a best-effort wake, not the source of truth. Per-request and benign, so surfaced at debug.

**What to do:** None — self-heals. A persistently unreachable callback is the caller's endpoint to fix; the recorded state remains pollable regardless.

<a id="a2a-own-card-build-failed"></a>
### BUSBAR-7008 — busbar's own agent card could not be built

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-own-card-build-failed`

busbar could not build its OWN agent card — the card that describes the A2A surface busbar publishes for callers. Without it, callers cannot discover busbar's agent surface. Usually a boot/config problem in the agent-plane definition.

**What to do:** Check the A2A plane configuration (agents, bindings, endpoint) for a malformed entry; busbar's own card is composed from it and could not assemble.

<a id="a2a-refuse-serve-card"></a>
### BUSBAR-7009 — Refusing to serve an agent card

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-refuse-serve-card`

busbar refused to serve an agent card for the named agent because the card could not be produced safely for this request (it failed to build or rewrite). The caller is refused rather than handed a card that leaks a backend or is malformed.

**What to do:** Check the named agent's registered card for a malformed or non-rewritable entry; the refusal names the agent so the offending registration can be corrected.

<a id="a2a-interrupted-task-unresumed"></a>
### BUSBAR-7010 — Interrupted A2A task could not be resumed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-interrupted-task-unresumed`

A task that had been interrupted could not be resumed, so the hop cannot continue from where it left off. The caller is answered with the failure; the task's stored state is unchanged. Usually the backend or the stored resumption context is no longer usable.

**What to do:** Inspect the named task and its backend: an interrupted task that cannot resume typically means the backend lost the session or the stored resume point is stale. The caller may re-submit.

<a id="a2a-inbound-task-unopened"></a>
### BUSBAR-7011 — Inbound A2A task could not be opened (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-inbound-task-unopened`

An inbound submission could not open a task — the durable row that records the task as submitted (and to whom it was dispatched) could not be created, so busbar refuses the request rather than run work it cannot account for. Typically a durable-store outage. Warned once on the transition; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. Inbound submissions resume once the store accepts writes again.

<a id="a2a-inbound-task-unrecorded"></a>
### BUSBAR-7012 — Inbound A2A task could not be recorded (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-inbound-task-unrecorded`

An inbound task was opened but its submission could not be written to the durable task store, so the caller is answered `503` rather than left with work that has no durable record. Typically a durable-store outage. Warned once on the transition into the failing state; subsequent failures hold at debug to avoid spam.

**What to do:** Investigate the durable task-store outage. Inbound submissions are recorded again once the store accepts writes.

<a id="a2a-outbound-cred-unleased"></a>
### BUSBAR-7013 — Outbound A2A credential could not be leased

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-outbound-cred-unleased`

busbar could not lease the outbound credential needed to make a hop to the target agent, so the hop is refused. The egress-auth path that mints or fetches the credential for this agent failed. Usually an egress-auth wiring or credential-source problem.

**What to do:** Check the egress-auth configuration and credential source for the named agent (scopes, the credential plugin/store). Outbound hops resume once a credential can be leased.

<a id="a2a-agent-binding-unspeakable"></a>
### BUSBAR-7014 — Registered agent card declares no binding busbar can speak

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-agent-binding-unspeakable`

The registered agent's card declares only bindings this build cannot speak, so the hop is refused HERE by name rather than relayed as an envelope the backend never offered to read. A backend that publishes only an unspeakable binding is unreachable to busbar. A registration/config problem, not a transient fault.

**What to do:** Register the agent with a binding busbar can speak, or upgrade busbar to a build that speaks the agent's binding; the log names the agent and the binding it declared.

<a id="a2a-relay-thread-incomplete"></a>
### BUSBAR-7015 — A2A relay thread did not complete (join failure)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-relay-thread-incomplete`

A relay worker thread did not complete cleanly — its join returned an error, which means the thread panicked or was cancelled mid-relay. The task's outcome for that hop is therefore unknown. An internal fault, not a backend refusal.

**What to do:** Capture the surrounding logs for the panic/backtrace and file it: a relay thread that does not join is a busbar-internal bug. The named task may need to be re-submitted.

<a id="a2a-push-notify-undelivered"></a>
### BUSBAR-7016 — A2A push notification was not delivered

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-push-notify-undelivered`

A push notification for a task's state change could not be delivered to the caller's registered callback (the callback is down or refused it). Never fatal to the task and never retried into a hammer: the outcome is recorded and the caller's poll will find it. Per-request and benign, so surfaced at debug.

**What to do:** None — self-heals. A persistently unreachable callback is the caller's endpoint to fix; the task's recorded state remains pollable regardless.

<a id="a2a-stream-empty"></a>
### BUSBAR-7017 — Backend stream carried no event

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-stream-empty`

A backend's streaming response ended without carrying any event, so the relay had nothing to forward for that task. Benign and per-request — an empty stream is a valid (if unusual) backend behaviour. Surfaced at debug so a chatty backend cannot spam.

**What to do:** None — self-heals. If backends routinely return empty streams, investigate the backend; busbar simply records that the stream carried nothing.

<a id="a2a-relayed-stream-refused"></a>
### BUSBAR-7018 — Relayed A2A stream ended in a refusal

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-relayed-stream-refused`

A relayed streaming task ended in a refusal from the backend rather than a normal completion. The refusal is recorded against the task and the caller's poll will find it. Per-request and expected under normal backend policy, so surfaced at debug.

**What to do:** None — self-heals. A stream that ends in a refusal reflects the backend's own decision; the recorded refusal is what the caller reads.

<a id="a2a-stream-relay-incomplete"></a>
### BUSBAR-7019 — A2A streaming relay thread did not complete (join failure)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-stream-relay-incomplete`

A streaming-relay worker thread did not complete cleanly — its join returned an error, which means it panicked or was cancelled mid-stream. The streamed task's outcome is therefore unknown. An internal fault, not a backend refusal.

**What to do:** Capture the surrounding logs for the panic/backtrace and file it: a streaming-relay thread that does not join is a busbar-internal bug. The named task may need re-submitting.

<a id="a2a-relayed-outcome-unrecorded"></a>
### BUSBAR-7020 — Relayed A2A task outcome could not be recorded (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-relayed-outcome-unrecorded`

A relayed hop SUCCEEDED and the caller is owed its answer, but the resulting state transition could not be written to the durable task store. Reported, never fatal: a store that refused the transition is an operator problem, not a reason to discard completed, billed work. Warned once on the transition; subsequent failures hold at debug.

**What to do:** Investigate the durable task-store outage. The caller still receives the completed hop; only the durable outcome record failed and resumes once the store accepts writes.

<a id="a2a-relayed-submission-failed"></a>
### BUSBAR-7021 — Relayed A2A task submission failed

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-relayed-submission-failed`

A relayed task submission was refused by the backend. The refusal is recorded against the task and returned to the caller; busbar did not accept work it could not place. Per-request and expected under normal backend policy or load, so surfaced at debug.

**What to do:** None — self-heals. A submission the backend refuses reflects the backend's own decision or capacity; the caller reads the recorded refusal and may re-submit.

<a id="a2a-breaker-refusal-unrecorded"></a>
### BUSBAR-7022 — Breaker-refused A2A task could not be recorded as rejected (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-breaker-refusal-unrecorded`

A submission was refused before the socket by the cross-plane breaker, but the resulting `rejected` transition could not be written to the durable task store. The caller still gets the `503` + `Retry-After`; the durable row is what could not be updated. Typically a store outage. Warned once on the transition; then held at debug.

**What to do:** Investigate the durable task-store outage. The caller received the breaker refusal; only the durable record of it failed and resumes once the store accepts writes.

<a id="a2a-failure-unrecorded"></a>
### BUSBAR-7023 — Failed A2A task could not be recorded as failed (durable store write failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-failure-unrecorded`

A task reached the terminal `failed` state but that transition could not be written to the durable task store, so a durable row may still claim the work is in flight. The caller is answered and any registered callback is fired; the durable record is what failed. Typically a store outage. Warned once on the transition; then held at debug.

**What to do:** Investigate the durable task-store outage. The caller was told of the failure; the durable `failed` record resumes once the store accepts writes.

<a id="a2a-task-rows-unreadable"></a>
### BUSBAR-7024 — Persisted A2A task rows could not be read back (not resumable)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-task-rows-unreadable`

At boot, some persisted A2A task rows could not be read back and are therefore NOT resumable — they were most likely written by a different engine version. Reported separately from the restored count and at warn, because folding an unreadable in-flight task into the restored total is how a task that silently ceased to exist across a deploy stays invisible.

**What to do:** Expected once after an engine-version change; the named rows cannot be resumed by this binary. If it recurs without a version change, inspect the durable task store for corruption. Callers of the affected tasks may re-submit.

<a id="a2a-task-state-unread"></a>
### BUSBAR-7025 — Durable A2A task state could not be read at boot (in-flight tasks start empty)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-task-state-unread`

At boot, the durable A2A task state could not be read at all, so busbar starts with NO in-flight tasks restored rather than block boot on the store. Any task that was in flight before restart is invisible to this process until the store answers. Typically a durable-store outage.

**What to do:** Investigate the durable governance/task store outage and restart once it is reachable so in-flight tasks are restored. Until then, busbar serves with an empty in-flight set.

<a id="a2a-card-fetch-panicked"></a>
### BUSBAR-7026 — Agent-card fetch panicked during an operator-driven verb

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-card-fetch-panicked`

While running an operator-driven verb, the agent-card fetch panicked rather than returning an error or a card. The operator's action could not complete. An internal fault on the fetch path, not a backend refusal.

**What to do:** Capture the surrounding logs for the panic/backtrace and file it: a card fetch that panics is a busbar-internal bug. Retry the operator verb once resolved.

<a id="a2a-reverify-cadence-unparsed"></a>
### BUSBAR-7027 — A2A re-verification cadence did not parse (registration keeps the release default)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-reverify-cadence-unparsed`

An agent registration's re-verification cadence did not parse, so the registration keeps the release-default cadence rather than the operator's intended value. Config validation should have refused this before boot; reaching this point means a bad cadence slipped through to registration.

**What to do:** Fix the named agent's re-verification cadence to a parseable value and reload. Until then, that agent re-verifies on the release-default cadence, not the configured one.

<a id="a2a-card-cert-no-spki"></a>
### BUSBAR-7028 — Card endpoint certificate yielded no SPKI pin

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `a2a-card-cert-no-spki`

When fetching an agent card over TLS, the endpoint's certificate yielded no SPKI pin, so busbar cannot pin the endpoint's key for that fetch. A trust/pin configuration problem: without an SPKI pin the card's transport cannot be pinned to a known key.

**What to do:** Check the card endpoint's TLS certificate and busbar's pinning configuration for that agent; a certificate that yields no SPKI cannot be pinned.

<a id="a2a-push-outcome-unchained"></a>
### BUSBAR-7029 — A2A push-notification delivery outcome could not be chained

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `a2a-push-outcome-unchained`

The outcome of a push-notification delivery could not be appended to its provenance chain. The delivery itself already happened (or was already refused); only the record-keeping append failed. Per-request and benign to the delivery path, so surfaced at debug.

**What to do:** None — self-heals for delivery. If it recurs, investigate the durable provenance store, since delivery outcomes are then going unchained.

<a id="mcp-calllog-empty-chains"></a>
### BUSBAR-7060 — Durable MCP call log enumerates principals with NO records

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-calllog-empty-chains`

At boot the durable MCP per-call log named one or more principals but returned no records for them, so their chains reopen at seq 1. The verifier cannot distinguish this from a caller's evidence being deleted wholesale, so it is surfaced rather than summed silently into the restored total.

**What to do:** Confirm whether these principals were expected to have call history. If they were, treat the durable governance store as possibly tampered and capture it for review before it is overwritten.

<a id="mcp-calllog-unread"></a>
### BUSBAR-7061 — Durable MCP per-call log could not be read at boot

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-calllog-unread`

The durable MCP per-call log could not be read back at boot, so the persisted tail is unknown and a principal that already has rows in the store may reopen its chain at seq 1 and collide with a persisted sequence number.

**What to do:** Check the durable governance store's health and connectivity. Once it answers, restart so the per-call chains restore from a known tail.

<a id="mcp-demotions-restored"></a>
### BUSBAR-7062 — MCP upstream demotions restored from the durable store

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-demotions-restored`

One or more MCP upstream servers were quarantined before the last restart and their demotion records were replayed from the durable governance store, so they are refused until an operator works the change or a sweep observes them serving what was approved.

**What to do:** Investigate why each named server was demoted and either remediate it or clear its demotion. Until then, requests routed to it are refused by design.

<a id="mcp-stdio-read-error"></a>
### BUSBAR-7063 — MCP stdio serve read error on stdin (session ending)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-stdio-read-error`

The MCP stdio server hit a read error on stdin and is shutting the session down. This is the expected outcome when the peer closes the pipe, so it is logged at debug rather than as an operator alert.

**What to do:** None — self-heals. Expected when a stdio MCP client disconnects.

<a id="mcp-ask-recogniser-missed"></a>
### BUSBAR-7064 — MCP input-required result reached the terminal check (ask recogniser missed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-ask-recogniser-missed`

An upstream MCP tool returned an input-required result that reached the terminal check without the ask recogniser catching it — an internal invariant breach, since such a result should have been recognised and handled earlier. The call is refused rather than handing the caller an upstream's demand for a secret.

**What to do:** Report the named tool and field: the ask-recognition path has a gap that let an input-required shape through. This is a code-level fix, not an operator misconfig.

<a id="mcp-output-schema-violation"></a>
### BUSBAR-7065 — MCP upstream structuredContent violates the published outputSchema

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-output-schema-violation`

An upstream MCP tool returned `structuredContent` that does not validate against the tool's own published `outputSchema`, so the result is refused. This is an upstream contract violation that can recur per request, so it is logged at debug to avoid spam.

**What to do:** If a specific tool trips this repeatedly, report the schema mismatch to that MCP server's operator. No local action is needed.

<a id="mcp-toolcall-refused"></a>
### BUSBAR-7066 — MCP tools/call refused by policy

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-toolcall-refused`

An MCP `tools/call` was refused by busbar's policy (budget, gate, or capability). This is a routine per-request governance outcome, logged at debug so a busy caller cannot spam the operator log.

**What to do:** None — self-heals. The refusal reason is recorded in the audit and call log if a specific caller needs to be understood.

<a id="mcp-toolcall-upstream-failed"></a>
### BUSBAR-7067 — MCP tools/call upstream failed

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-toolcall-upstream-failed`

An MCP `tools/call` was dispatched and the upstream server failed to execute it. This is reported to the model as a tool execution error (not a busbar refusal) and can recur per request, so it is logged at debug.

**What to do:** None locally — self-heals. If a specific upstream fails persistently, check that server's health.

<a id="mcp-toolcall-refused-pre-upstream"></a>
### BUSBAR-7068 — MCP tools/call refused before the upstream

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-toolcall-refused-pre-upstream`

An MCP `tools/call` was refused before it reached the upstream (a pre-dispatch policy denial). Routine per-request governance, logged at debug to avoid spamming the operator log under load.

**What to do:** None — self-heals. The refusal reason is in the audit and call log.

<a id="mcp-caller-ask-refused"></a>
### BUSBAR-7069 — MCP caller-ask refused

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-caller-ask-refused`

A caller's MCP ask for a capability was refused by policy. This is a routine per-request governance outcome, logged at debug so it cannot spam the operator log.

**What to do:** None — self-heals. The refusal reason is recorded in the audit and call log.

<a id="webhook-exporter-disabled"></a>
### BUSBAR-7070 — Webhook log exporter disabled (invalid configuration)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `webhook-exporter-disabled`

A request-log webhook exporter could not be built from its configuration and has been disabled, so its request logs are NOT delivered. This is a config problem surfaced at boot, not a transient delivery failure.

**What to do:** Fix the named webhook exporter's configuration (URL, auth header, or projection) and restart to re-enable delivery.

<a id="webhook-delivery-non-2xx"></a>
### BUSBAR-7071 — Webhook log delivery returned non-2xx (log dropped)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `webhook-delivery-non-2xx`

A request-log webhook delivery got a non-2xx response from the sink, so that one log line was dropped (deliveries are fire-and-forget and never retried). This can recur per request when a sink is unhealthy, so it is logged at debug.

**What to do:** If logs are being lost, check the webhook sink's health and the delivery counters. `WEBHOOK_LOGS_DROPPED_TOTAL` tracks the volume.

<a id="webhook-delivery-transport-error"></a>
### BUSBAR-7072 — Webhook log delivery transport error (log dropped)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `webhook-delivery-transport-error`

A request-log webhook delivery failed with a transport error (connection/timeout/DNS), so that one log line was dropped. Deliveries are fire-and-forget and never retried; this can recur per request when a sink is unreachable, so it is logged at debug.

**What to do:** If logs are being lost, check the webhook sink's reachability and the delivery counters. `WEBHOOK_LOGS_DROPPED_TOTAL` tracks the volume.

<a id="file-log-append-failed"></a>
### BUSBAR-7073 — Request-log file append failed (log dropped)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `file-log-append-failed`

Writing a line to the request-log file failed, so that log line was dropped. Telemetry writes are fire-and-forget and never block serving, but a persistent failure means request logs are being lost — usually a disk-full or permission problem.

**What to do:** Check the log file's path for free space and write permission. Serving is unaffected; only request-log durability is.

<a id="file-log-open-failed"></a>
### BUSBAR-7074 — Request-log file open failed (log dropped)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `file-log-open-failed`

The request-log file could not be opened for append, so that log line was dropped. A persistent failure means request logs are being lost — usually a missing directory, a permission problem, or a full disk.

**What to do:** Ensure the log file's directory exists and is writable, and that the disk is not full. Serving is unaffected; only request-log durability is.

<a id="file-log-retention-failed"></a>
### BUSBAR-7075 — Request-log archive retention cleanup failed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `file-log-retention-failed`

During rotation, deleting the oldest request-log archive failed, so the archive series may grow past its retention limit and consume more disk than intended. No log data is lost by this failure itself.

**What to do:** Check the log directory's permissions and free space so retention cleanup can remove the oldest archive on the next rotation.

<a id="file-log-shift-failed"></a>
### BUSBAR-7076 — Request-log archive shift failed during rotation

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `file-log-shift-failed`

Renaming an archived request-log file to its next slot during rotation failed, so the older archive was left in place rather than lost. Rotation degrades but no recorded data is discarded.

**What to do:** Check the log directory's permissions and that no external process holds the archive files, so the shift can complete on the next rotation.

<a id="file-log-rotate-rename-failed"></a>
### BUSBAR-7077 — Request-log rotation rename failed (file grows past cap)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `file-log-rotate-rename-failed`

Renaming the current request-log file to its first archive slot failed, so busbar keeps APPENDING to the current file rather than truncating it — no recorded data is lost, but the file will grow past its `rotate_mb` cap until this is resolved.

**What to do:** Check the log directory's permissions and free space so the rotation rename can succeed. No data is lost in the meantime; the file simply exceeds its size cap.

<a id="ir-clamp-n-to-1"></a>
### BUSBAR-7078 — Cross-protocol transcode clamped n>1 to 1

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-clamp-n-to-1`

On a cross-protocol hop the neutral response IR carries a single candidate, so a request asking for n>1 completions is clamped to n=1 before the egress writer emits it — otherwise extra choices would be generated, billed, and then dropped. Fires per request on the affected seam, so it is logged at debug.

**What to do:** None — self-heals. To use n>1, route the request to a same-protocol lane where the body is forwarded verbatim.

<a id="ir-drop-reasoning"></a>
### BUSBAR-7079 — Cross-protocol transcode dropped a reasoning/thinking ask

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-drop-reasoning`

A request's reasoning/thinking parameter was dropped on the cross-protocol seam because the target lane does not declare the reasoning capability; the request proceeds at the backend's default thinking level. Fires per request on the affected seam, logged at debug.

**What to do:** None — self-heals. Set `reasoning: true` on the model or pool member if the backend accepts thinking params.

<a id="ir-drop-prompt-cache"></a>
### BUSBAR-7080 — Cross-protocol transcode dropped prompt-cache breakpoints

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-drop-prompt-cache`

Prompt-cache breakpoints were cleared on the cross-protocol seam because the target lane's dialect gates its cache marker per model and the lane does not declare the capability; the request proceeds uncached. Fires per request on the affected seam, logged at debug.

**What to do:** None — self-heals. Set `prompt_caching: true` on the model if the backend accepts cache markers (e.g. Claude on Bedrock).

<a id="ir-drop-cache-control-over-cap"></a>
### BUSBAR-7081 — Cross-protocol transcode dropped cache_control breakpoints past the dialect cap

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-drop-cache-control-over-cap`

The request carried more cache_control breakpoints than the egress dialect allows (the target vendor 400s past its documented cap), so the breakpoints past the cap were dropped before the writer emitted them. Reachable only cross-protocol; fires per request, logged at debug.

**What to do:** None — self-heals. Reduce the number of cache breakpoints, or route to a same-protocol lane if the full set is load-bearing.

<a id="ir-drop-hosted-tools"></a>
### BUSBAR-7082 — Cross-protocol transcode dropped hosted (built-in) tools

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-drop-hosted-tools`

One or more Responses hosted (built-in) tools were dropped on the cross-protocol seam because they have no function-tool equivalent for a non-Responses backend; forwarding them would emit a malformed empty-name function tool the upstream rejects. Fires per request, logged at debug.

**What to do:** None — self-heals. Route hosted-tool requests to a Responses lane to use them.

<a id="ir-drop-message-name"></a>
### BUSBAR-7083 — Cross-protocol transcode dropped OpenAI messages[].name

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-drop-message-name`

OpenAI per-message participant names (`messages[].name`) were dropped on the cross-protocol seam because no target protocol models a per-message speaker name, so a multi-speaker transcript reaches the backend with its speaker labels removed. Fires per request, logged at debug.

**What to do:** None — self-heals. Put the speaker in the message text, or route to an openai lane.

<a id="ir-drop-cached-content"></a>
### BUSBAR-7084 — Cross-protocol transcode dropped Gemini cachedContent

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-drop-cached-content`

A Gemini `cachedContent` reference was dropped on the cross-protocol seam because the referenced context cache lives server-side at Google and cannot be projected into `contents`: the backend answers on the visible history only and the caller is billed full uncached input. Fires per request, logged at debug.

**What to do:** None — self-heals. Route cachedContent requests to a Gemini lane to use the cache.

<a id="ir-drop-unmodeled-keys"></a>
### BUSBAR-7085 — Cross-protocol transcode dropped unmodeled request keys

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-drop-unmodeled-keys`

The source dialect's unmodeled top-level request keys were dropped on the cross-protocol seam because no target writer can re-emit a foreign dialect's key, so every key named in the log is not forwarded to the backend. Fires per request; only key names are logged (never their values), at debug.

**What to do:** None — self-heals. Route to a same-protocol lane (which forwards the caller's original bytes verbatim) if a named field is load-bearing.

<a id="ir-truncate-stop-sequences"></a>
### BUSBAR-7086 — Stop sequences truncated to the protocol's documented cap

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `ir-truncate-stop-sequences`

The request carried more stop sequences than the target protocol's documented cap allows, so the excess were dropped before forwarding. Fires per request on the affected seam, logged at debug.

**What to do:** None — self-heals. Reduce the number of stop sequences, or route to a same-protocol lane if the full set is required.

<a id="proto-auth-invalid-header-bytes"></a>
### BUSBAR-7087 — Egress credential has invalid header bytes (auth header omitted)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `proto-auth-invalid-header-bytes`

An egress authorization credential contained bytes that are not valid in an HTTP header (e.g. an ASCII control character), so the Authorization header was omitted entirely rather than sent malformed — the upstream will reject the request with 401. The key itself is never logged, only the protocol name. This is a bad-credential misconfig that can recur per request, so it is logged at debug.

**What to do:** Fix the misconfigured lane's credential — the configured secret contains invalid header bytes. The protocol name in the log line locates the lane.

<a id="proto-drop-provider-metadata"></a>
### BUSBAR-7088 — Cross-protocol transcode dropped response-side provider metadata

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `proto-drop-provider-metadata`

Response-side provider metadata (a Bedrock guardrail `trace`, a Gemini `safetyRatings`) was dropped on the cross-protocol seam because it is a vendor-scoped artifact the caller's protocol has no shape to receive. Fires per response on the affected seam, logged at debug.

**What to do:** None — self-heals. If this metadata is compliance evidence, route the request to a same-protocol lane where the upstream body reaches the client verbatim.

<a id="plane-task-row-unreadable"></a>
### BUSBAR-7089 — Persisted A2A task row could not be read back (not resumable)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-task-row-unreadable`

A persisted A2A task row could not be decoded at boot, so that task is NOT resumable and is reported rather than skipped silently. Usually an engine-version mismatch or a corrupt row.

**What to do:** Note the task id. If many rows are unreadable, suspect a store format mismatch after an upgrade or downgrade; capture the store for review.

<a id="plane-ssrf-callback-at-store"></a>
### BUSBAR-7090 — SSRF-refused push callback reached the task store (dropped)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-ssrf-callback-at-store`

A push callback URL that the SSRF guard refuses reached the A2A task store and was dropped there. The store is the last line of defence — a callback should have been validated by the caller before it got this far, so reaching the store means a caller path skipped validation.

**What to do:** Find the caller that stored this callback without validating it (a code-level defect in a submission path) and add the SSRF check before the store.

<a id="approval-ledger-unreachable-refused"></a>
### BUSBAR-7091 — Spent-approval ledger unreachable — redemption refused

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `approval-ledger-unreachable-refused`

The shared spent-approval ledger could not be reached, so an approval redemption was REFUSED: a ledger that cannot say whether an approval was already spent must not be read as saying it was not (a double-spend on a money-moving tool is the defect the gate exists to stop).

**What to do:** Restore connectivity to the shared spent-approval ledger's durable store. Until then, approval redemptions fail closed by design.

<a id="plane-calllog-empty-chain"></a>
### BUSBAR-7092 — Durable MCP call log enumerates a principal with NO records

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-calllog-empty-chain`

The durable MCP call log named a principal and then produced no records for it, so its chain is reopened at seq 1 and the discrepancy is reported rather than skipped. The verifier alone cannot distinguish this from a caller's evidence being deleted wholesale.

**What to do:** Confirm whether this principal was expected to have call history. If it was, treat the store as possibly tampered and capture it for review before it is overwritten.

<a id="plane-calllog-write-failed"></a>
### BUSBAR-7093 — Durable MCP per-call record could not be written (evidence lost)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-calllog-write-failed`

The durable MCP per-call record could NOT be written, so this call is being served but its evidence is being lost. The chain position is unchanged, so the chain stays contiguous — what is missing is this one record, not the ones after it. This can recur per request during a store outage, so it warns on the transition into the failing state and holds subsequent occurrences at debug.

**What to do:** Restore the durable governance store's write path. Once writes succeed again the latch resets and a future outage re-warns.

<a id="plane-demotion-write-failed"></a>
### BUSBAR-7094 — Durable MCP demotion record could not be written

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-demotion-write-failed`

The durable MCP demotion record could NOT be written, so this upstream is demoted only in the current process and a restart will re-open it until the next sweep looks again. Usually a durable store-write outage.

**What to do:** Restore the durable governance store's write path so demotions persist across restarts.

<a id="plane-demotion-clear-failed"></a>
### BUSBAR-7095 — Durable MCP demotion record could not be cleared

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-demotion-clear-failed`

The durable MCP demotion record for an upstream could NOT be cleared even though it is serving again in the current process, so a restart would re-establish a quarantine the operator has already worked. Usually a durable store-write outage.

**What to do:** Restore the durable governance store's write path so a cleared demotion does not reappear after a restart.

<a id="plane-demotions-unread"></a>
### BUSBAR-7096 — Durable MCP demotion records could not be read at boot

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `plane-demotions-unread`

The durable MCP demotion records could NOT be read at boot, so any upstream this deployment had demoted is re-opened until the first sweep looks again. Usually a durable store-read outage.

**What to do:** Restore the durable governance store's read path and restart so persisted demotions are re-applied before a listener binds.

<a id="trust-verify-refused-on-drift"></a>
### BUSBAR-7097 — Verify-on-call refused a call because the upstream's advertised surface drifted

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `trust-verify-refused-on-drift`

On the request path, verify-on-call re-fetched the upstream's advertised surface (an MCP tool's name+args+description, or an A2A agent card) within `verify_ttl` and found it DRIFTED from the fingerprint the operator approved, so the call was refused BEFORE dispatch. The refusal itself is the signal; this is a warn-once-per-subject note so persistent drift does not spam.

**What to do:** Review the change on the trust surface and re-approve the new fingerprint if it is legitimate, or investigate the upstream if it is not.

<a id="trust-verify-unreachable"></a>
### BUSBAR-7098 — Verify-on-call could not reach an upstream to re-verify, and refused fail-closed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `trust-verify-unreachable`

On the request path, verify-on-call needed to re-verify an upstream whose recorded observation was older than `verify_ttl`, and the re-fetch FAILED (unreachable or unverifiable). The call was REFUSED fail-closed rather than served against a snapshot older than the operator's bound. Latched per subject.

**What to do:** Restore reachability to the named upstream. Calls to it are refused until a re-fetch succeeds within `verify_ttl`; a larger `verify_ttl` widens the drift-serving window and is an explicit, documented security downgrade.

## 8xxx — Governance & cost

<a id="revocation-resync-outstanding"></a>
### BUSBAR-8001 — Revocation denylist re-sync still outstanding from an earlier window

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `revocation-resync-outstanding`

A revocation-denylist re-sync launched in an earlier window has not returned — the governance store has not answered for at least a full sync window — so busbar keeps serving the last-known revocations and does not start a second overlapping read. A peer's revoke may not be visible on this node until the store recovers. The CAS bound rate-limits this warning to once per window.

**What to do:** Investigate the governance store's health and latency. Revocations already known stay enforced (fail-closed); the risk is a NEW revoke made elsewhere not yet reaching this node. Re-sync resumes automatically once the store answers.

<a id="revocation-resync-failed"></a>
### BUSBAR-8002 — Revocation denylist re-sync failed (keeping the previously-known revocations)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `revocation-resync-failed`

A revocation-denylist re-sync read from the governance store returned an error, so busbar keeps the previously-known revocations in place (fail-closed: a store blip never widens access) and leaves the set marked stale so the next window retries. A peer's revoke may not be visible on this node until a later sync succeeds.

**What to do:** Investigate the governance store — a transient error self-heals on the next window's retry; sustained failures mean the store is unreachable and cross-node revocations are not propagating.

<a id="governance-key-reserved-namespace-collision"></a>
### BUSBAR-8003 — Refused to synthesize a governance key (principal id collides with a reserved namespace)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `governance-key-reserved-namespace-collision`

A principal id (attacker-influenceable at the IdP) starts with a reserved ledger-bucket prefix (`group:` or `vk_`), which would alias a group's or a real virtual key's ledger and rate bucket. busbar fails closed and synthesizes NO key for that principal rather than mint a colliding bucket. This is a per-request, caller-side signal, not an operator problem, so it is emitted at debug.

**What to do:** None — self-heals; the principal is correctly refused data-plane access. If a legitimate identity is being rejected, its IdP subject must be reshaped to avoid the reserved `group:` and `vk_` prefixes.

<a id="limit-window-unrecognized"></a>
### BUSBAR-8004 — Unrecognized limit window (enforcing as all-time 'total')

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `limit-window-unrecognized`

A limit's window word was not recognized — it can only arise from a corrupt or foreign store row, since config parse rejects unknown windows. busbar fails SAFE and enforces the limit as the all-time ('total') window, the tightest enforcement, never wider, and surfaces the value so the corruption is visible instead of silent.

**What to do:** Inspect the governance store row for the named window value — it was written by something other than a validated config load. Enforcement is safe (all-time) in the meantime; correct the row so the intended window applies.

<a id="refresh-self-inconsistent-binding"></a>
### BUSBAR-8005 — Self-serve refresh left an inconsistent binding (tombstone AND rollback both failed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `refresh-self-inconsistent-binding`

During a self-serve key refresh, tombstoning the prior binding failed and the compensating rollback of the newly-minted binding ALSO failed, so the subject may now have TWO live bindings in the store for one identity. busbar exhausted its best-effort recovery and surfaces the inconsistent state for inspection. Rare.

**What to do:** Inspect the governance store for the named subject — it may hold two live bindings (old_id and new_id). Tombstone whichever is not intended so the subject has exactly one valid credential.

<a id="refresh-self-cache-refresh-failed"></a>
### BUSBAR-8006 — Self-serve refresh: cache reconcile failed after tombstoning the prior binding

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `refresh-self-cache-refresh-failed`

During a self-serve key refresh, the store tombstone of the prior binding committed but the follow-up cache reconcile (a store round-trip) failed. busbar evicted the prior binding directly from the cache so its old token stops verifying immediately; the store is consistent, but the rest of the cache may be stale until the next successful refresh.

**What to do:** Investigate the governance store's reachability — the durable state is correct and the old credential no longer verifies. The cache self-heals on the next successful reconcile; sustained failures mean the store is unhealthy.

<a id="accrual-group-missing"></a>
### BUSBAR-8007 — Group missing at accrual (tokens ledgered to the key bucket only)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `accrual-group-missing`

A group referenced by a key was gone by the time usage was accrued (the group was deleted between admission and accrual), so busbar degrades to ledgering the tokens on the key's own bucket only rather than lose them. The request was already admitted and served; nothing is lost. This is a per-request, self-degrading path, so it is emitted at debug.

**What to do:** None — self-heals; tokens are preserved on the key bucket. Frequent occurrence for one key means a group is being deleted out from under active keys; reconcile the key's group assignment.

<a id="metering-flush-partial-failure"></a>
### BUSBAR-8008 — Metering flush: some keys failed to persist this tick (retained for retry)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `metering-flush-partial-failure`

A metering flush tick could not persist one or more keys' usage deltas to the store. busbar retains the failed deltas and retries them on the next tick, so no usage is lost. This is already collapsed to ONE aggregate warning per tick (per-key detail is at debug), so it fires at a human cadence, not per key.

**What to do:** Investigate the governance store if the failure count stays non-zero across ticks — a transient store hiccup self-heals on the next flush. Usage is retained and re-tried, so billing is not lost, only delayed.

<a id="delete-key-cache-reconcile-failed"></a>
### BUSBAR-8009 — delete_key: tombstone committed and key evicted, but cache reconcile failed

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `delete-key-cache-reconcile-failed`

An admin key deletion committed the tombstone in the store and evicted the deleted key from the in-memory caches (it no longer authenticates), but the follow-up full cache reconcile failed. The deletion is durable and the key is dead; only OTHER cache entries may be stale until the next successful refresh. Rare admin path.

**What to do:** Investigate the governance store's reachability — the deletion itself is complete and safe. The cache self-heals on the next successful refresh; sustained failures indicate an unhealthy store.

<a id="rotate-key-cache-reconcile-failed"></a>
### BUSBAR-8010 — rotate_key: new generation committed, but cache reconcile failed (new secret not returned)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `rotate-key-cache-reconcile-failed`

An admin key rotation committed the new generation in the store — so the PREVIOUS credential is permanently dead — and evicted the key from the caches, but the follow-up cache reconcile failed, so the freshly-minted secret could not be returned to the admin. The rotation IS durable; the new secret is simply lost from this response. Rare admin path.

**What to do:** Re-rotate the key to obtain a fresh secret — the previous credential is already dead and will not come back. Investigate the governance store's reachability, which is why the reconcile failed.

<a id="budget-flush-partial-failure"></a>
### BUSBAR-8011 — Budget flush: some buckets failed to persist this tick (re-marked dirty for retry)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `budget-flush-partial-failure`

A budget flush tick could not persist one or more group-budget buckets to the store. busbar re-marks those buckets dirty and retries them on the next tick, so no spend is lost. This is already collapsed to ONE aggregate warning per tick (per-bucket detail is at debug), so it fires at a human cadence, not per bucket.

**What to do:** Investigate the governance store if the failure count stays non-zero across ticks — a transient store hiccup self-heals on the next flush. Spend is retained and re-tried, so budgets are not lost, only delayed.

<a id="safe-mode-overlay-quarantined"></a>
### BUSBAR-8012 — SAFE MODE: config overlay not merged (running on base config.yaml alone)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `safe-mode-overlay-quarantined`

busbar was booted with `--safe-mode`, so the persisted config overlay (API-registered hooks) was NOT merged and busbar is running on the operator-owned base config.yaml alone. This is the intentional escape hatch for an applied hook that harms traffic and re-applies itself every boot. The overlay file is untouched, not deleted.

**What to do:** This is an operator-requested state. Repair or remove the offending overlay entry, then boot WITHOUT `--safe-mode` to re-apply the overlay. Until then, API-registered hooks are not in effect.

<a id="provider-api-key-unresolved"></a>
### BUSBAR-8013 — Provider api_key did not resolve (degraded to an empty key)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `provider-api-key-unresolved`

A provider's `api_key` secret reference did not resolve at boot, so busbar degraded that provider to an empty key. This is legitimate for keyless local upstreams (ollama/vLLM), but for a real provider it means egress will be unauthenticated and the upstream will reject with 401.

**What to do:** If the provider needs a key, fix its `api_key` secret reference (the secret is missing or the resolver could not read it) and restart. If the upstream is genuinely keyless, no action is needed.

<a id="open-relay-no-auth"></a>
### BUSBAR-8014 — auth.chain is empty — OPEN RELAY (every request admitted unauthenticated)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `open-relay-no-auth`

The auth chain is empty (either explicitly, or because the `auth:` block is absent and serde-defaults to none), so every data-plane request is admitted unauthenticated — an OPEN RELAY forwarding anyone's traffic on your upstream credentials. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr so the state cannot be masked by log configuration. Acceptable only for local development.

**What to do:** Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing busbar to any untrusted network. This is the same open-relay condition as BUSBAR-4004, surfaced at boot.

<a id="store-secret-ref-unresolved"></a>
### BUSBAR-8015 — Store settings hold a secret reference that does not resolve here

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `store-secret-ref-unresolved`

A governance-store `settings` value holds a secret reference that does not resolve on this boot. busbar warns rather than fails, because the store is restart-to-apply and staging a ref whose secret the orchestrator mounts on the next deploy is a legitimate workflow. But if the secret is still absent at the next restart, THAT restart will fail in resolve_settings before serving.

**What to do:** Ensure the named store secret reference resolves before the next restart. If you are staging it for an upcoming deploy, no action now; otherwise fix the reference so the next restart does not die resolving it.

<a id="governance-store-ephemeral"></a>
### BUSBAR-8016 — Governance store is in-memory (ephemeral) — state resets on restart

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `governance-store-ephemeral`

busbar selected the in-memory (ephemeral) governance store, so virtual keys, groups' usage, and ledgers live only in RAM and are LOST on restart. This is the default when no durable store plugin is configured — fine for a trial or local development, but not for anything that must retain keys or spend across restarts.

**What to do:** Configure a durable governance store plugin for persistence if keys, usage, or budgets must survive a restart. No action is needed for ephemeral/dev use.

<a id="durable-keys-inert"></a>
### BUSBAR-8017 — Durable keys are inert (keys exist but `keys` is not in the running auth chain)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-keys-inert`

A durable governance store holds virtual keys, but the running auth chain does not include the `keys` verifier, so those keys enforce nothing — every request bypasses key-based governance. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr, the same pattern as the open-relay banner, so the inert state cannot be masked by log configuration.

**What to do:** Add `keys` to `auth.chain` so the durable keys actually gate traffic, or remove the keys if key-based governance is not intended. Until then, minted keys are dead weight.

<a id="group-usage-read-failed"></a>
### BUSBAR-8018 — Group usage read failed (could not derive a bucket's usage from the governance store)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `group-usage-read-failed`

An admin group `/usage` read could not derive a bucket's usage from the governance store (a store read error while computing enforcement-matched spend), so the request returns 500 rather than a partial or understated usage view. No governance state is mutated; the read simply could not complete for the named group/bucket.

**What to do:** Investigate the governance store's health for the logged group and bucket (reachability, the underlying store error). The condition is a read-path fault; usage reads recover once the store answers.

<a id="metering-pending-overflow-coalesced"></a>
### BUSBAR-8019 — Metering accumulator at cap: a cell was coalesced into an overflow sentinel

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `metering-pending-overflow-coalesced`

The write-behind metering accumulator (pending_metering) reached its cap while a NEW (key_id, bucket, model, provider) cell arrived — a sustained governance-store outage with diverse keys/models, where every flush re-queues the failed cells while new ones keep arriving. Rather than grow without bound OR silently drop billable usage, busbar COALESCES the arriving cell's counts into a per-bucket overflow sentinel: the day's token and request TOTALS are preserved, only their per-key/model/provider ATTRIBUTION is collapsed. Each coalesce also increments busbar_metering_pending_coalesced_total. Per-event detail is at debug; this is the human-cadence signal.

**What to do:** Restore the governance store — the accumulator overflows only under a sustained write outage. Usage is not lost (totals are retained under the overflow sentinel key), but once the store recovers the retained deltas flush and normal per-key attribution resumes. A steadily climbing coalesced counter means the outage has outlasted the cap.

## 9xxx — Boot & lifecycle

<a id="boot-audit-restore-read-failed"></a>
### BUSBAR-9001 — Durable audit log could not be read at boot (starting with an empty ring)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `boot-audit-restore-read-failed`

busbar could not READ the durable audit log from the governance store at boot — a store hiccup, not a chain-verification failure — so it started with an empty in-memory audit ring. This is deliberately distinct from BUSBAR-2001 (chain verification failed): here the bytes could not be read at all, so there is no tamper signal, just a store that did not answer.

**What to do:** Investigate the governance store's reachability at boot. If the store recovers, restart so the durable history is restored into the ring; a transient hiccup needs no action beyond confirming the store is healthy.

<a id="tls-accept-persistent-failure"></a>
### BUSBAR-9002 — TLS accept loop failing persistently (backing off)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `tls-accept-persistent-failure`

The TLS listener's accept loop is failing persistently — commonly file-descriptor exhaustion — so busbar backs off before retrying rather than spin hot on the error. The warning is already rate-limited by the backoff delay, so it fires at a human cadence, not per failed accept.

**What to do:** Investigate the accept failure — most often the process fd limit (raise `ulimit -n` / the systemd `LimitNOFILE`) or a resource leak holding sockets open. The listener keeps retrying with backoff and recovers on its own once accepts succeed.

<a id="telemetry-slot-table-full"></a>
### BUSBAR-9003 — Telemetry slot table full (further label sets fall back to the metrics macros)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `telemetry-slot-table-full`

The telemetry bank's pre-registered slot table reached its cap, so further label sets fall back to the ordinary metrics macros instead of a reserved slot — correct, just slower on that path. Warned ONCE per table (a latch), never per registration, so it cannot spam.

**What to do:** None — self-heals; the fallback path is correct. If a deployment legitimately needs more distinct label sets than the slot cap, that cap is a build-time bound; the metrics remain accurate via the fallback in the meantime.

<a id="eventstream-eventtype-header-oversize"></a>
### BUSBAR-9004 — Event-stream :event-type header exceeds the string cap (frame dropped)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `eventstream-eventtype-header-oversize`

An event-stream `:event-type` header exceeded the AWS type-7 string cap, so busbar dropped the frame rather than emit a malformed one. This is unreachable for any real Bedrock event name (the only caller-supplied value on the frame); it guards the data path and fires per-frame, so it is emitted at debug.

**What to do:** None — self-heals per frame; a real Bedrock event name never trips it. Sustained occurrence would mean a caller is supplying an over-long event-type, worth checking the ingress path.

<a id="eventstream-exceptiontype-header-oversize"></a>
### BUSBAR-9005 — Event-stream :exception-type header exceeds the string cap (frame dropped)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `eventstream-exceptiontype-header-oversize`

An event-stream `:exception-type` header exceeded the AWS type-7 string cap, so busbar dropped the exception frame — a swallowed mid-stream error signal — rather than emit a malformed one. It fires per-frame on the streaming data path and is near-unreachable for a real exception type, so it is emitted at debug.

**What to do:** None — self-heals per frame. If it recurs, an upstream mid-stream error carried an over-long exception-type name; check the egress dialect mapping for that upstream.

<a id="eventstream-frame-oversize"></a>
### BUSBAR-9006 — Event-stream frame exceeds MAX_FRAME_BYTES (frame dropped)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `eventstream-frame-oversize`

An event-stream frame's total size exceeded MAX_FRAME_BYTES, so busbar dropped it rather than byte-truncate the payload (a truncated JSON body is worse for a native SDK than no frame). Unreachable for any real Bedrock ConverseStream delta; it only guards a pathological multi-MiB single event and fires per-frame, so it is emitted at debug.

**What to do:** None — self-heals per frame; dropping is graceful (nothing is emitted for that event). Sustained occurrence would indicate an upstream emitting abnormally large single events, worth investigating that lane.

<a id="boot-fatal-error"></a>
### BUSBAR-9007 — Boot refused (fatal misconfiguration or startup error; process exits non-zero)

- **Severity:** fatal
- **Since:** 1.6.0
- **Slug:** `boot-fatal-error`

The binary hit a fatal startup condition — a misconfiguration or other boot-time failure the process cannot serve past — so it printed a single-line reason to stderr and exited non-zero rather than a Rust panic backtrace. The specific reason is printed alongside this code. This is a deliberate refusal, not a crash.

**What to do:** Read the printed reason, fix the underlying config/environment problem, and restart. `busbar --validate` reproduces most boot refusals without binding a listener.

<a id="worker-threads-invalid"></a>
### BUSBAR-9008 — Configured worker-thread count is invalid (ignored; default used)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `worker-threads-invalid`

An explicitly-set worker-thread count — `TOKIO_WORKER_THREADS`/`advanced.worker_threads` — is not a positive integer (e.g. `0`, or non-numeric), so busbar IGNORES it and boots on the default worker-thread count. The operator's intended thread count is NOT in effect. Emitted pre-tracing, to stderr, at boot.

**What to do:** Set the worker-thread count to a positive integer (at least 1) or remove it to accept the default. The gateway runs, but on the default thread count, not the value provided.

<a id="shutdown-signal-handler-install-failed"></a>
### BUSBAR-9009 — Shutdown-signal handler not installed (that signal won't trigger graceful drain)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `shutdown-signal-handler-install-failed`

A graceful-shutdown signal handler (SIGINT/ctrl_c, SIGTERM on unix, or CTRL_CLOSE/CTRL_SHUTDOWN on Windows) failed to register. busbar fails soft — that one branch parks forever so the others still trigger the drain — but a stop delivered ONLY via the failed signal will kill the process without draining in-flight requests.

**What to do:** Investigate the logged registration error (an unusual sandbox or signal-handling environment). Other shutdown signals still drain; if the affected signal is your deployment's stop path, restart in an environment where it can register.

<a id="jemalloc-idle-purge-fallback-unavailable"></a>
### BUSBAR-9010 — jemalloc idle-purge fallback unavailable (idle RSS may not return to the OS)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `jemalloc-idle-purge-fallback-unavailable`

The fallback idle-purge helper (for targets where jemalloc's background purge threads are compiled out, e.g. static-musl or macOS) could not start — its worker thread failed to spawn, or it could not read `opt.dirty_decay_ms`. A fully IDLE process may therefore hold freed-but-unpurged dirty pages and its RSS can ratchet at the last burst's peak until traffic resumes. Request behavior is unaffected.

**What to do:** Usually benign — RSS is reclaimed the moment traffic resumes, and under load the helper does nothing. If steady idle RSS on a musl/macOS build matters, investigate the logged spawn/mallctl error; the gateway serves normally regardless.

<a id="signing-key-generation-failed"></a>
### BUSBAR-9011 — --generate-signing-key could not mint a key (OS entropy source unavailable)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `signing-key-generation-failed`

`busbar --generate-signing-key` could not mint a fresh ed25519 signing secret because the OS entropy source was unavailable, so it printed nothing and exited non-zero. No key was generated and nothing was written.

**What to do:** Retry on a host with a working RNG (`/dev/urandom` / `getrandom`). A persistent failure points at a broken or blocked entropy source in the environment.

