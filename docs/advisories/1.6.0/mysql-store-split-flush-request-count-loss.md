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
(`governance/state.rs`, `try_admit` pass 2: `cell.requests += 1`, before any model/upstream is
known) and accrues its tokens at COMPLETION, while the write-behind flusher ticks on its own
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

Fixed as a **contract** change rather than a MySQL-specific patch, because the durable ledger's
shape is Busbar's to define and backends implement it:

- `Store::add_usage`'s contract now states explicitly that request counters are BUCKET-level,
  that `models` may legitimately be empty on a given delta, and that a conforming backend MUST
  make the request-count portion of a delta durable independently of any per-model row
  (`crates/api/src/store.rs:1046-1055` and the `UsageDelta::requests` field doc,
  `crates/api/src/store.rs:602-611`).
- A new conformance cell, `assert_usage_survives_reopen_atomically`
  (`crates/plugin-testkit/src/store_conformance.rs`), drives exactly the two-flush admission/
  completion sequence through `add_usage` and requires the whole `UsageLedger` back across a
  reopen — all fields or none. The existing reopen check could not see this defect because it
  wrote one complete ledger in a single `put_usage` call, which a model-keyed backend satisfies
  trivially.
- The new cell is proven able to fail: `RequestsKeyedByModel`, a reference backend built with the
  defect on purpose (`crates/plugin-testkit/src/tests/store_conformance_tests.rs`), is required to
  both trip the ruling and be shown to have kept the tokens — spend survives, the requests cap
  does not — which is what makes this a money defect and not merely "wrote nothing."
- `MemoryStore` and the file-backed `store-example-plugin` are both wired to the new ruling as
  reference implementations (`crates/store-memory/tests/store_conformance.rs`,
  `crates/store-example-plugin/src/tests/mod.rs`).

The published MySQL store plugin itself is fixed by re-publishing it against the corrected
contract and conformance suite; this repository fixes and proves the contract the plugin must
satisfy.

## Evidence

- The store-contract fix ("store contract: a usage ledger is ONE accounting record, and the request
  count was not in it"), 2026-09-11, `main`/`dev` line — full measurement (run counts, backend
  comparison, failing-row readback) is in the commit body; files touched: `crates/api/src/store.rs`,
  `crates/busbar-core/src/governance/tests/limits_tests.rs`,
  `crates/plugin-testkit/src/store_conformance.rs`,
  `crates/plugin-testkit/src/tests/store_conformance_tests.rs`,
  `crates/store-example-plugin/src/tests/mod.rs`, `crates/store-memory/tests/store_conformance.rs`.
- Internal audit ledger (`gate/held.txt`), OWNER ITEM NOTE-86: "the published mysql store loses
  request counts on a split flush (1/40 at default cadence) — running 1.5.5 deployments are not
  fixed until 1.6.0 ships; advisory at the tag."
- CHANGELOG.md: **not found.** As of this worktree's tip (`143db6db6`), `CHANGELOG.md` has no
  entry naming MySQL or the split flush. This advisory exists to record the disclosure the
  changelog does not yet carry; a Changelog `### Security` or `### Fixed` line should be added
  alongside it (not written here, to avoid asserting a changelog entry that has not landed).

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
