# `busbar-oracle record --filter` records ZERO cells for every pattern

**Status:** CLOSED 2026-09-22. Fixed in `GetBusbar/busbar-release` at `89718d8`
(`fix/oracle-recorder-residual-gaps`), pinned by `oracle-rust.pin`, plus the `--out` fix in
`bin/oracle` committed alongside this file.

**Engine refs originally exercised:** `77d5793` and `338575545c`. The diagnosis below REPLACES this
document's original "suggested repair", which guessed at selection and guessed wrong.

## The premise was right; the cause was not selection

The ids exist and the patterns match. Over the committed `cells.json` (2318 cells), measured:

| filter | ids matched |
|---|---|
| `billing` | 14 |
| `^billing\|` | 14 |
| `^(billing\|ledger\|config)\|` | 20 |
| `ledger` | 6 |
| `zzz-no-such-cell` | 0 |

`select_cells` is **byte-identical** between `77d5793` and the ref this was re-measured on, and
called directly against the real corpus it returns exactly those counts. So selection never dropped
anything. The original symptom was **SELECTED N, RECORDED 0**, not "selected 0" — two different
faults that look identical from outside, which is why this document's first guess went to the wrong
place.

What caused the original zero: this file's own §"Why it matters" records the condition — *three
agents' oracle recordings running concurrently against the same fixed port band*. A recording binds
its listen/admin/mock ports only while a cell runs, so concurrent runs on a FIXED band collide
mid-run and every cell fails; `recorded == 0` then trips `ZERO ROWS IS RED`. `00759df`
("claim a port band per run, and refuse loudly instead of degrading") fixed that, and at the current
pin filtered recording measurably works:

- `--filter '^billing\|'` → 14 ledger rows, **12 PASS**, 2 SKIP (one named corpus gap, one mock that
  did not come up).
- `--filter 'ledger'` → 6 rows, **6 PASS**.

## Three real defects found while measuring it, all now fixed

1. **`--filter` was accepted and discarded** (engine). `HarnessArgs::into_config()` hardcoded
   `id_filter: String::new()`, so every path except `record --native` took the flag and ignored it.
   Measured: `replay --filter 'zzz-no-such-cell'` printed the same **913 DIVERGED rows** as an
   unfiltered replay. A pattern matching nothing narrowed nothing, silently.
2. **`--family` sat in `--filter`'s slot** (engine). `drive_record()` pushed the family into
   `record.sh --filter` and never passed the id regex. As an ID regex, `core` matches every id
   *containing* "core" in any plane and misses every `plane: core` cell that does not spell it —
   all 14 `billing|*` cells among them.
3. **`bin/oracle record --out <dir>` wrote somewhere else and said it had not** (this repo). It
   passed only `--work-dir`, letting the recorder write `<work>/candidate`, then printed that the
   `--out` basename *"is honored as that dir"*. Measured: `--out /tmp/x/money` wrote the recording
   to `/tmp/x/candidate`, left `/tmp/x/money` **empty**, and exited **0** saying "recorded 1
   cell(s)". Any caller that named its own output dir then read an empty directory — a working
   recorder reading as a broken one, and the most likely shape of "0 cells" for anyone re-running
   this by hand. The engine has taken `--out-dir` for exactly this since the native cutover;
   `bin/oracle` now passes it.

## A zero-match filter says so, and does not borrow `ZERO ROWS IS RED`

Already true at the pinned engine and re-verified here — a gap and a failure are not the same
output. `--filter 'zzz-no-such-cell'` exits **1** with:

> selected 0 cells: plane 'all' + filter 'zzz-no-such-cell' over a 2318-cell corpus (2318 cell(s)
> are in that plane). That filter matches no cell id anywhere in the corpus. Note the ids are the
> PIPE-separated form (`ledger|amend|adjusting-entries`), not the recording's file name
> (`ledger__amend__adjusting-entries`). Recording nothing is never a pass — a run that covered none
> of what you asked for must not be shaped like a run that covered all of it.

and writes **no** `ledger.tsv` and **no** `meta.json`, so nothing is left behind that a later reader
could mistake for a thin-but-clean recording.

## Regressions guarding this

- `the_filter_flag_reaches_the_harness_config` — `--filter` survives into the config; `--family`
  stays its own field.
- `record_sends_the_plane_to_plane_and_the_id_regex_to_filter` — the two selectors reach their own
  flags. On the prior code it fails printing the bug verbatim: `[…, "--filter", "core"]`, no
  `--plane`, no id regex.
- `a_filter_that_selects_nothing_is_a_loud_refusal` / `a_filter_that_selects_something_still_runs` —
  the empty-selection refusal fires, and does not fire on a merely small selection.
