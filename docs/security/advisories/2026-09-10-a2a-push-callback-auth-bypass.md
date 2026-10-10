# Advisory: A2A push-callback authorisation — three defects in the same control (never expired, then acted-on-too-late)

## Summary

The a2a plane's push-event callback authorisation had **three** distinct defects, found and fixed
across the same 2026-09-07 sweep, all in the leg that decides whether a push callback may move a
task:

1. **Wrong primitive, and never expired.** The leg authorised a callback by calling
   `redeem_plane_token(kind, key.id, key.ts, key.ts)` — passing the same value as both the deadline
   and the clock. That asks the store "is `now` past `now`", which is never true, so no token ever
   failed the expiry check. Underneath, the neutral store verb's `Ok(true)` default meant a token
   failed nothing at all: a callback token captured off the wire could keep moving its task for as
   long as the process lived, including after the task had already finished.
2. **The check was recorded, not enforced.** After the first fix introduced a real liveness check,
   the result was asked and answered and then **every later leg in the plan ran regardless** — "a
   check whose result is recorded next to the write it was supposed to prevent is not a check." A
   dead token's liveness was correctly computed as false and then ignored.
3. **(Related, not a defect in itself.)** The a2a root's record-leg dispatch duplicated a
   schema/operation check that the kernel's `PlaneRecord` runner (see the separate
   `2026-09-10-kernel-planerecord-validation.md` advisory) now owns; the duplicate was removed so
   validation lives in exactly one place.

Fixed by, in order: (1) adding a `plane_token_live` verb that is read-only, spends nothing, and
fails closed (`Ok(false)`) by default, replacing the single-use `redeem_plane_token` (right for
approval nonces, wrong for a token presented multiple times per task), and giving `LegKey` a real
`expires_at` distinct from the arrival clock; (2) making a dead-token answer stop the plan **at the
check**, first, before any leg that records a move — a refused callback now writes nothing and
appends no provenance event, and both refusal tests assert the write count is unchanged, not just
that a refusal occurred.

## Affected versions (measured)

**None released.** The a2a plane does not exist at `v1.5.5`:
`git ls-tree -r v1.5.5` contains no `a2a` paths at all. The plane was introduced by `7297ca212`
("busbar-transport-{tcp,tls,http,sse}, busbar-plane-{mcp,a2a}: four transports and two planes on
the contract"), 2026-09-04, and the root wiring that contains the vulnerable call
(`crates/busbar/src/root/units_a2a.rs`) is later still (`331f4be9f`, "busbar 1.6.0 root: the A2A
plane driven through the kernel"). Neither is an ancestor of `v1.5.5`. The exact vulnerable
expression `redeem_plane_token(kind, key.id, key.ts, key.ts)` does not appear anywhere in the
`v1.5.5` tree (`git grep` at that tag returns nothing).

## Fixed in

Landed hashes (picks in parens — a pick and its landed twin are different commit objects in this
repo's flow, so measurement below is against the landed hashes), all 2026-09-07:

- `26b4eaa2f` (pick `20fa6b4d4`) — store ABI: add the neutral `plane_token_live` verb, fail-closed
  by default.
- `86ac2e227` (pick `4f7e15a07`) — a2a plane: authorise a push callback by liveness, and revoke on
  the ending.
- `9420280a3` (pick `527e8951c`) — a2a root: stop the push callback leg verifying every token it is
  shown.
- **`698344993`** (pick `6457d0314`) — a2a root: act on the liveness answer instead of filing it
  beside the write (defect 2 above).
- Related, not itself a vulnerability fix: `3058afbb9` (pick `53812f0b4`) — a2a root: the record
  arm calls the kernel's runner; removes the duplicate schema/operation check (defect 3 above).

All are ancestors of this worktree's base (`ad8887f2b`). **Not present on any released branch** per
`git branch -r --contains <hash>`: not on `origin/dev`, `origin/qa`, or `origin/main` — the a2a
plane does not exist there at all. Not applicable to any released line.

## Severity (per SECURITY.md's scale)

Would be **Critical** (authentication/capability bypass on the a2a plane — a captured token
acting indefinitely — matching SECURITY.md's "Authentication bypass" scope item) had it ever
shipped. As measured, it did not.

## Exposure statement

The a2a plane is entirely unreleased; it was introduced and had this defect for its entire
existence prior to the fix, all within unreleased 1.6.0 development. No tagged version, including
`v1.5.5` (current), ever contained the a2a plane. **No advisory is owed to operators and no CVE is
warranted.**

## Backport

None owed. No released line ever carried the a2a plane.

## Credit

Internal audit.
