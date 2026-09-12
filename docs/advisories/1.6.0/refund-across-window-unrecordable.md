# Advisory: a refund that crosses a billing-window rollover cannot be recorded, because a key has no billing window

## Id

ADV-1.6.0-4

## Classification

Not a SECURITY.md-scoped vulnerability; a measurement gap in the oracle/conformance suite that
traces to a real product limitation. Recorded as an advisory because the underlying cause —
per-key usage is tracked in a single all-time bucket, not a rolling window — is a fact an
operator sizing refund/proration behavior needs, even though nothing here is exploitable.

## Summary

The oracle/conformance effort attempted to record a `billing|key-usage|refund-across-window`
cell — a request whose refund (e.g., a non-2xx or cancelled response) lands after a billing
window has rolled over from the window the original charge was posted in — and could not,
because the precondition the cell needs does not exist in the product: **a key has no billing
window to roll over.**

`busbar-core`'s admin usage-overview endpoint reports every key's accrual bucket in the
**all-time** window unconditionally:

```rust
json_response(
    StatusCode::OK,
    json!({
        "id": id,
        "budget_period": crate::governance::WINDOW_TOTAL,
        ...
```

(`crates/busbar-core/src/admin/mod.rs`, near line 2060 in the current tree; the ledger's original
measurement cites `admin/mod.rs:2054` against the commit/branch it was taken from — line numbers
differ slightly by commit but the finding is the same code path.) `WINDOW_TOTAL` is the literal
string `"total"` (`crates/busbar-core/src/governance/mod.rs:29`), and the accrual/refund
bookkeeping keys off it explicitly rather than off any per-window bucket derived from a
configured period: `state.rs:817` accrues into `super::WINDOW_TOTAL`, and `state.rs:2046`
(`refund_bucket(&key.id, super::WINDOW_TOTAL, now)`) refunds into the same all-time bucket. A
key's limits, where configured, live on its bound GROUP's windows (per the governance model), not
on the key's own accrual bucket — so there is no key-level "window" for a refund to cross.

## Affected versions

1.5.x and 1.6.0 alike; this is the current, unchanged governance model, not a regression.

## Impact

None on shipped behavior — a refund is applied correctly to the one all-time bucket that exists.
The impact is entirely on **measurement**: the conformance suite cannot exercise a
window-rollover refund scenario against real per-key accounting, because the scenario requires a
key-level rolling window (e.g., "minute", per the ledger's proposed test lever) that the product
does not implement. Any operator expecting a refund to reconcile correctly against a per-key
rolling budget window (as opposed to a group-level one) should note that key-level budgeting is
all-time only today.

## Ruling

Owner item, not yet decided: whether key-level billing windows (as opposed to the existing
group-level windows) are a wanted 1.6.0 or later feature. Per the ledger: "refund-across-window
unrecordable on 1.5.5 — admin/mod.rs:2054 hardcodes budget_period=total, window_start=0; no
key-level billing window exists (owner: a 1.6.0 tariff-window question, not a tool gap)." **Not
found:** no owner ruling on whether to add key-level windows is recorded in the ledger as of this
writing; this advisory records the open question rather than a decision.

## Evidence

- `crates/busbar-core/src/admin/mod.rs` (near line 2060 in this tree) — the usage-overview
  handler reporting `budget_period: WINDOW_TOTAL` unconditionally.
- `crates/busbar-core/src/governance/mod.rs:29` — `WINDOW_TOTAL` sentinel definition.
- `crates/busbar-core/src/governance/mod.rs:869` — `WINDOW_TOTAL => 0` (explicit all-time window
  start).
- `crates/busbar-core/src/governance/state.rs:817,1493,1559,2046` — accrual and refund bookkeeping
  keyed to `WINDOW_TOTAL` for a key's own bucket.
- Internal audit ledger (`gate/held.txt`): "needs_fixture still: ... billing|key-usage|
  refund-across-window (OR-OP-2 owed)"; and, after investigation, "refund-across-window
  unrecordable on 1.5.5 — admin/mod.rs:2054 hardcodes budget_period=total, window_start=0; no
  key-level billing window exists (owner: a 1.6.0 tariff-window question, not a tool gap)."

## Remediation / operator action

None required for current behavior; refunds against the existing all-time key bucket and
group-level windows are unaffected. An operator who needs rolling-window refund/proration
accounting at the individual-key level (rather than the group level) should raise this as a
feature request; it is explicitly not implemented today and not committed to any release.

## Backport

Not applicable — no defect to backport.

## Credit

Internal audit.
