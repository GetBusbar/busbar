# Migration corpus

Every `config.yaml` busbar has ever shipped, and the `providers.yaml` that shipped beside it, from
every non-rc git tag. `crates/busbar/tests/migration_corpus.rs` migrates each one with
`busbar --migrate-config` and asserts the result is a config the CURRENT binary accepts.

## Why real files, not fixtures

Hand-written fixtures contain the shapes somebody thought of. The shapes that break people are the
ones nobody thought of — a field that quietly aged out three releases ago and still sits in a
config somewhere.

This corpus exists because of
[terraform-provider-busbar#8](https://github.com/GetBusbar/terraform-provider-busbar/issues/8): an
acceptance harness carried a config shape that had been retired, the gateway refused to boot, and
nothing noticed until a daily poll went red. It had two independent breaks, and the first masked
the second — config validation stops at the first error, so fixing the reported problem only moved
the failure. A corpus finds every era's break at once, before a release, not after.

## Adding a release

```
tests/migration-corpus/refresh.sh
```

Regenerates both directories from tags. Run it after cutting a release so the new version joins the
corpus; the test discovers the directory, so no code changes. It is idempotent and rewrites from
scratch, so a file removed upstream disappears here too.

## What the test actually asserts

1. **It migrates** without error.
2. **The output validates.** Not "the migrator exited 0" — a migrator emitting syntactically valid
   nonsense also exits 0. The migrated config must pass `busbar --validate`.
3. **Decisions the migrator defers are supplied, and only those.** It cannot invent a signing key or
   choose an admin credential, and it says so via `TODO(migrate)` rather than guessing. The test
   supplies exactly those two. Supplying more would be the test hiding a real migration gap.
4. **A migration needing no decision emits no comment banner** — the output should be
   indistinguishable from a file somebody wrote by hand.

Each config is validated against **its own tag's** providers catalog. `bench/latency/config.mock.yaml`
names a `mock` provider that exists only in `bench/latency/providers.mock.yaml`; validating it
against the root catalog reports a true statement about the wrong pairing, not a migration defect.

## When it fails

The failure names the corpus file, the validator's own words, the first 30 lines of the migrated
config, and the exact command to reproduce. **Fix the migrator, not the corpus** — the corpus is
evidence of what shipped, and editing it to go green deletes the evidence.
