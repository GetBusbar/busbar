> **STOP: owner decision on disclosure.** The vulnerable code is measured present in shipped
> `v1.5.5` and is **still present, unfixed, on `origin/dev`, `origin/qa`, and `origin/main` today**.
> This advisory is written in-tree only. Do not publish, file a GitHub Security Advisory, or
> request a CVE until an owner has decided disclosure timing and a backport/forward-fix plan —
> per SECURITY.md, the fix must land on `dev` first and flow forward, and nothing has yet.

# Advisory: admin mutation rate limiter — config blast-radius limit bypassable via clock regression

## Summary

`MutationLimiter::check` (per-principal, per-`MutationClass` fixed-window admin rate limiting)
swept its window map with `map.retain(|_, (w, _, _)| *w == window)` — "drop every entry not in the
current window" — using a wall clock (`SystemTime::now()`, read as `0` on failure) recomputed on
every call. Wall clocks are not monotonic (NTP correction, or a container starting before its
host's time syncs). A single request carrying an older `now` recomputes an older window and the
`==` sweep drops *every* live counter in the map, for every principal and class, not just the
caller's own — refilling everyone's budget. This is a bypass of the config-mutation blast-radius
limit for anything able to nudge, or simply observe an already-skewed, wall clock.

Fix: track a monotone `latest_window` high-water mark under the same lock as the sweep, judge each
arrival against `arrived_in.max(latest_window)`, and sweep only entries strictly older than that
clamped window (`*w >= window` with the clamp, never `*w == window`). A regressed clock can now
only make the current window last longer (erring toward refusal), never open a fresh one early.

## Affected versions (measured)

**Shipped, and currently unfixed on all live branches.**

- The vulnerable `*w == window` sweep is present at the `v1.5.5` tag (the current published
  release; `testing/shadow-oracle/golden/1.5.5/meta.json`, `binary_sha256: 84bde0a0…`):
  `git show v1.5.5:crates/busbar/src/admin/rate.rs` line 183.
- It is present today, unfixed, on:
  - `origin/main` (`crates/busbar/src/admin/rate.rs`)
  - `origin/dev` (`crates/busbar-core/src/admin/rate.rs`, post core-split)
  - `origin/qa` (same path)
- The feature itself dates back further still (`c90081a9f`, "1.3 admin: per-principal mutation
  rate limits (spec 6.6)"); this repo's history has been rewritten enough since (rebase/land.sh
  re-pinning per this repo's own convention) that `git merge-base --is-ancestor` no longer connects
  that commit to `v1.5.5`, but the vulnerable expression's presence in the `v1.5.5` tree itself is
  a direct, unambiguous measurement independent of ancestry.
- The fixed copy lives only in `crates/busbar-unit-verbs/src/rate.rs`, a 1.6.0-only crate — the
  fix has not been ported back onto the `crates/busbar/…` (main) or `crates/busbar-core/…`
  (dev/qa) copies that operators are actually running today.

## Fixed in

- `d747f5831` — "mutation rate limiter: sweep only windows strictly older than the current one,
  and clamp a regressing clock" (cherry-picked from `1974379e9`), 2026-09-07.
- Present on `origin/integration/oracle-phase0` and its `keep-*` descendants (1.6.0 development
  line only). **Not present on `origin/dev`, `origin/qa`, or `origin/main`** — the fix has not
  reached any branch that would ship it, because it was written against the 1.6.0
  `busbar-unit-verbs` copy of the limiter, not the `busbar`/`busbar-core` copy that `v1.5.5`, `dev`,
  `qa`, and `main` all still run.

## Severity (per SECURITY.md's scale)

**High.** This is a bypass of an admin-plane protection (the config-mutation blast-radius limit)
reachable by anything able to observe or nudge the process's wall clock — not a full
authentication bypass, but a control that exists specifically to bound the blast radius of
mutation abuse, defeated network-wide (all principals, all classes) by one out-of-window request.
Matches SECURITY.md's "Admin-plane isolation" and general DoS/abuse-control scope. Under the
policy's Critical/High backport window (latest two minor lines), this qualifies for backport once
disclosed.

## Exposure statement

**The vulnerable code shipped in `v1.5.5` and remains unfixed in the code operators are running
today (`main`) and in the lines under active development (`dev`, `qa`).** This is not a
pre-release-only finding like the other three items in this sweep. A fix exists but is stranded on
an unreleased 1.6.0 architectural fork of the limiter (`busbar-unit-verbs`) that has not been
forward-ported to the shipped copy. Per SECURITY.md's own policy ("Fix on `dev` first, always"),
the fix is currently on the wrong side of that rule — it needs to land on `dev` against the
copy `dev` actually runs, not only on the 1.6.0 integration branch.

## Backport

**Owed, pending owner decision.** Per policy this is High severity: fix on `dev` first (porting
the clamp to `crates/busbar-core/src/admin/rate.rs`), flow through `qa` to `main`, and backport to
the previous supported minor line. A GitHub Security Advisory and CVE request are due once an
owner sets disclosure timing — do not open one from this document alone.

## Credit

Internal audit.
