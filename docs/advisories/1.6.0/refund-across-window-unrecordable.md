# Advisory: a failed request that straddles a billing-window roll kept its flat fee on 1.5.5

## Id

ADV-1.6.0-4

## Classification

Not a SECURITY.md-scoped vulnerability; a billing-accuracy defect in 1.5.x, fixed in 1.6.0 as a
deliberate, owner-signed change (1.6.0 CHANGELOG, Changed: "a failed request's flat fee is
refunded from the window bucket it was charged to, even when that bucket has rolled into the next
window"). Recorded as an advisory because the 1.5.x figure an operator read off a group's usage
view could be one fee too high, and because the scenario was long treated as unmeasurable.

## Summary

Busbar charges a request's flat `per_request_fee` at admission and refunds it when the request
fails (a non-2xx outcome). Both halves are keyed off the request's arrival epoch, so they land in
the same window of each windowed bucket (a group's `per: minute | hour | day | ...` limits).

A **window straddle** breaks that pairing. Request A reads the clock just before a window
boundary (window D); request B reads it just after (window D+1) and reaches the group's window
cell first, rolling it to D+1. A's charge then lands in place on the D+1 cell, which is correct:
the charge rule accepts a cell holding the request's window or a newer one.

- **1.5.x** refunded only a cell whose window *equalled* the request's own. The rolled cell holds
  D+1, so when A failed its refund was a no-op and its fee stayed on the D+1 bucket for the rest of
  that window: the group's reported spend and the budget it enforces read one fee too high.
- **1.6.0** refunds the cell the charge reached (a cell holding the request's window or a newer
  one), the exact inverse of the charge. A cell *older* than the request's window is still a no-op
  on both.

A key's own accrual bucket is the all-time window, which never rolls, so the key usage view was
correct on both; only windowed group buckets were affected.

## Measured

The oracle cell `billing|key-usage|refund-across-window` records this against the published
1.5.5 binary and the 1.6.0 candidate. It reproduces the straddle deterministically by moving the
binary's wall clock between two requests (`testing/shadow-oracle/fixtures/clock-shift.c`,
preloaded by `testing/shadow-oracle/scripts/refund-across-window.sh`): B is served at
D+1 00:00:01, then A arrives at D 23:59:30 with its upstream down (503). With
`per_request_fee: 7` and B's tokens priced at 250 cents, the group's D+1 day bucket reads:

| | requests | tokens | spend_cents | budget_remaining_cents |
|---|---|---|---|---|
| 1.5.5 | 2 | 18 | 264 | 999736 |
| 1.6.0 | 2 | 18 | 257 | 999743 |

The key's all-time bucket reads 257 cents on both.

## Affected versions

1.5.x (every release with windowed group limits and a non-zero `per_request_fee`). Fixed in 1.6.0.

## Impact

Over-billing by one `per_request_fee` per failed straddling request, on the group bucket of the
window the straddle rolled into, for the life of that window. Reachable only when a failed request
and a concurrent admission race across a window boundary, so rare in practice; a group budget near
its cap could refuse a request it should have admitted.

## Ruling

Owner ruling 2026-09-28: ship 1.6.0's behaviour (the refund reaches the bucket the charge
reached). The difference is registered as a breaking entry in
`testing/shadow-oracle/accepted-differences.json` ("M-1 refund reaches the cell the charge
reached") with a premise that holds the 1.6.0 figures above exactly.

Separately, a key has no billing window of its own (its bucket is all-time, and a key's limits
live on its group's windows); whether key-level windows are wanted is a product question this
advisory does not decide.

## Remediation / operator action

Upgrade to 1.6.0. No configuration change is needed. On 1.5.x, a group's windowed spend can be
over-stated by one fee per affected request until the window rolls.

## Backport

Not planned.

## Credit

Internal audit.
