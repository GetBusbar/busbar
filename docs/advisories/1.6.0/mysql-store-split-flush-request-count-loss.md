# Advisory: the published MySQL store plugin loses request counts on a split flush

## Id

ADV-1.6.0-2

## Classification

Money/billing-correctness defect in a first-party store backend. Touches SECURITY.md's scope
only tangentially (it is a governance/billing-cap integrity issue, not a credential or auth
issue); severity is assessed below by analogy to SECURITY.md's scale rather than against one of
its named Scope bullets, since none names store-backend write atomicity directly. Recorded here
on the same disclosure basis as a Security entry because it silently resets an operator's
requests-based rate limit.

## Summary

Measured directly against the **published 1.5.5 binary** and its digest-pinned published store
plugins (`plugins.store-persist|store-mysql`): a request occasionally (about 1 run in 40 at the
default 100 ms write-behind flush cadence; about 6 in 10 with `advanced.usage_flush_interval_ms:
1`) comes back after a restart with `requests 1 -> 0` while `spend_cents` and `tokens` are
untouched. A failing run's durable row reads back as
`requests=0 billable_requests=0 tokens_input=11 tokens_output=7` — the token write landed, the
request-count write did not. Postgres, Valkey and SQLite show 0 failures in 20 runs at either
cadence; only the MySQL backend loses the count.

### Mechanism

Not a hydration race — a **split flush**. The engine charges a request at ADMISSION
(`crates/busbar-kernel/src/governance/state.rs`, before any model or upstream is known) and accrues its tokens at COMPLETION, while the write-behind flusher ticks on its own
interval (100 ms by default). A request slower than one flush tick is therefore written to the
store as **two separate deltas**: `{requests: +1, models: []}`, then later `{requests: 0,
models: [<tokens>]}`. A backend that keys its request counters off its per-`(bucket, window,
MODEL)` rows has nowhere to place a delta whose `models` list is empty — the
published MySQL store returns `Ok(())` for that delta and silently drops it. After a restart the
key's spend is intact but its `requests` counter is back at zero, so a restarted node hands a
requests-capped key a full fresh allowance it has not earned.

## Affected versions

Every published 1.5.x release running the MySQL store plugin (`plugins.store-persist|store-mysql`).
Confirmed against the published 1.5.5 binary and its pinned MySQL plugin artifact; not present in
the first-party Postgres, Valkey or SQLite backends at any measured cadence. The MySQL store
plugin ships out-of-tree (as a first-party plugin artifact), so there is no in-repo `mysql*.rs`
source to cite by path in this repository; the contract it must satisfy is fixed in-tree (see
Evidence).

## Impact

A requests-capped API key intermittently regains its full requests budget across a restart
without the operator's knowledge — a budget-bypass of the requests dimension specifically
(spend/token accounting is unaffected). An operator relying on the MySQL store for
requests-per-window enforcement should treat that enforcement as probabilistic, not exact, on
every 1.5.x release to date.

## Fix (1.6.0)

Fixed as a **contract** statement rather than a MySQL-specific patch, because the durable ledger's
shape is Busbar's to define and backends implement it. In 1.6.0 the usage delta a store receives
(`UsageDelta`, `crates/busbar-contract/src/records.rs`) carries the bucket-level `requests` and
`billable_requests` counts as fields of their own, apart from the per-model token rows in `models`,
and `UsageDelta::is_zero` treats a delta as empty only when the request counts and every model delta
are all zero. A conforming store therefore has to make the request-count portion of a delta durable
independently of any per-model row. The store plugin is fixed by re-publishing it against that
contract; the plugin's own release notes and conformance run carry that proof, not this tree.

## Evidence

- `UsageDelta` and `UsageLedger` in `crates/busbar-contract/src/records.rs`: the contract shape
  above.
- The defect itself was measured against the published 1.5.5 binary and its published MySQL store
  plugin, and the fix landed in the 1.6.0 line (commit `5e3c13044`, 2026-09-11). The MySQL store is
  published out of tree, so there is no in-repo source to cite for it.

## Remediation / operator action

Upgrade to 1.6.0 for the fixed contract and the re-published MySQL store plugin. Operators who
depend on exact requests-per-window enforcement on a 1.5.x MySQL-backed deployment should treat
that limit as advisory rather than a hard ceiling until upgraded, or switch to Postgres/Valkey/
SQLite in the interim, none of which exhibited the defect at either measured flush cadence.

## Backport

Per SECURITY.md's backport policy, backport eligibility is Critical/High-only; this is a billing
integrity defect with no confidentiality/authentication/authorization dimension, so it does not
meet that bar on its own. No 1.5.x patch tag is proposed here; disclosed at the 1.6.0 tag as the
ledger's own ruling directs ("advisory at the tag"). An owner override to backport is possible if
the requests-cap-bypass angle is judged security-relevant enough to warrant it — not ruled here.

## Credit

Internal audit.
