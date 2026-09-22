# `busbar-oracle record --filter` records ZERO cells for every pattern

**Status:** open, engine-side. Filed from the busbar side; the fix belongs in
`GetBusbar/busbar-release` (`busbar-release-oracle`), not here.

**Engine refs exercised:** `oracle-rust.pin` at `77d57937cf4b69114cc7b84be2012828fc992206` and at
`338575545c07cfded73d3da6ca88ca65a6742666`. Both behave identically.

## What the flag claims

`busbar-oracle record --help`:

> `--filter <FILTER>`  `--filter <regex>` on the cell id (native record), matching
> `record.sh --filter` [default: ""]

`bin/oracle` forwards it verbatim: `${FILTER:+--filter "$FILTER"}` in the `record)` arm.

## What it does

Every invocation below recorded **0 cells** and exited 1 with
`record --native: recorded 0 cells for candidate -> <out> — ZERO ROWS IS RED`:

| invocation | result |
|---|---|
| `./bin/oracle record --bin B --plane all  --out O --filter '^(billing\|ledger\|config)\|'` | 0 cells |
| `./bin/oracle record --bin B --plane all  --out O --filter 'billing'` | 0 cells |
| `./bin/oracle record --bin B --plane core --out O --filter '^billing'` | 0 cells |
| engine directly, `--family core --filter 'ledger'` | 0 cells |
| engine directly, no `--family`, `--filter 'ledger__'` | 0 cells |

The same command **without** `--filter` records normally: `--plane all` reached 403 cells before it
was stopped, and `--plane core` reached 148.

## The ids demonstrably exist

From `testing/shadow-oracle/cells.json` (2318 cells), and each of these is a `PASS` row in the
committed golden `testing/shadow-oracle/golden/1.5.5/ledger.tsv`:

- `billing|rate-card|history-mid-window`
- `billing|admin-usage|after-2`
- `billing|admin-usage|past-day`
- `ledger|amend|adjusting-entries`
- `ledger|amend|refused-unsigned`
- `ledger|rate-history|as-of`
- `ledger|currency|native`
- `ledger|currency|minor-unit-rounding`
- `config|rate-card|append-not-replace`

An unfiltered `--plane all` recording of the candidate wrote
`cells/billing__rate-card__history-mid-window.json`, so the cell is reachable by the recorder; only
the filter cannot select it. The `__`-separated form is the on-disk **file** name; the `|`-separated
form is the id in `cells.json` and in `ledger.tsv`. Patterns matching either spelling were tried and
both answered 0, so this is not simply a separator mismatch in the caller.

Note also that `--plane` matches the cell's `plane` field, whose only values are
`a2a | core | llm | mcp` (plus `all`) — `--plane billing` is refused with a helpful message. So
`--plane` is not a substitute for `--filter`: the money families (`billing` 14 cells, `ledger` 5,
`config` 1) all live under `plane: core`, which is 789 cells.

## Why it matters

A whole-plane run is the smallest unit of recording available, and on a shared box that is hours.
Measured on this machine with three agents' oracle recordings running concurrently against the same
fixed port band: **~1.5-3 cells/min** in the exec/boot families, i.e. ~4h for `--plane core` and
~10h for the full corpus. A money change that needs the `billing|*` and `ledger|*` verdict - 20
cells - cannot get one in reasonable time, so it either ships unmeasured or blocks a machine for a
shift. That is the whole cost of this defect.

## Suggested repair

Two things worth checking together in the engine's native recorder:

1. **Which string the filter is matched against**, and whether the match runs before or after the
   family/plane selection narrows the set. A filter ANDed against an already-empty set, or matched
   against a struct field that is not the id, both present as "0 cells" with no diagnostic.
2. **A zero-match filter should say so.** `ZERO ROWS IS RED` is the right verdict for an unfiltered
   run and the wrong message for a filter that selected nothing: the two cases want different text,
   and the filtered one should name the pattern and the number of ids it was matched against.

A cheap regression for it: `--filter '^billing\|'` must select exactly the 14 `billing|*` cells of
`cells.json`, and `--filter 'no-such-cell'` must fail with a message naming the pattern.
