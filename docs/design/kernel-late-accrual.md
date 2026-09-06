# The late accrual, on the LLM plane

*busbar 1.6.0 — the two edge cases, decided and measured.*

The exit settles what it knows **at the terminal**. On the LLM plane a delivered answer's
money is not among it: the response's completion tap fills its cell when the **body is
consumed**, which is after the terminal handed the client its bytes, after the audit door
sealed the end, and after the in-flight slot went back to the table. The metering step
therefore priced zero on every delivered unit, `Posted::settle` settled zero, a settlement of
zero is not a row, and `/api/v1/admin/ledger/totals` answered `{"rows":[]}` for a node whose
legacy rows carried a full day's spend. The identity held over an empty table and said so.

A figure that arrives after the terminal is a **late accrual** — ARCHITECTURE §2.2's own
vocabulary, and the same shape the loop already posts when a child's spend misses its
parent's exit. It goes onto the same principal, the same window, the same lane and provider
row, through `Posted::settle_late`, flagged `LATE_ACCRUAL | OVERDRAFT`.

Two questions the shape does not answer on its own. Both are decided here, and both were
measured rather than assumed.

---

## 1. A client that hangs up mid-body

**Decision: post what the tap reported, flagged — which is exactly what the legacy path
bills on the same event.**

This is not a policy chosen for the new leg. It is the legacy behaviour, read off the arm
that produces it.

`FirstByteBody::drop` (`crates/busbar-llm/src/engine/response_body.rs`) is the arm that runs
when a streamed body is dropped before its natural end — a client disconnect or a
cancellation. It does two things, in this order:

1. It **fills the tap** with `TapFinish::Partial`, the usage the readers accumulated up to
   the drop point, and `billing_failed` set from the same terminal-error / abort / stream-cut
   predicate the clean end uses.
2. If that predicate is false, it **bills** those tokens through the one accrual seam
   (`usage::ledger_and_meter`), because the tokens were really generated and really delivered
   before the caller went away. Its own comment names the alternative as "an under-billing on
   every cancel".

So on a hangup the legacy path bills the partial, and on a cut that surfaced a terminal error
or an aborted translation it bills nothing at all.

The late accrual reads **that same cell**, through the same predicate, and posts the same
figure:

- `billing_failed == false` → the tier the tap accumulated is priced against the card the
  admission pinned, and posted, flagged late.
- `billing_failed == true` → the tier is empty by construction, the price is zero, and a zero
  is not a row. Nothing is posted. The exit's own settlement already fully describes the unit.

The two agree **by construction rather than by coincidence**: there is one cell, one
predicate and one pricing expression (`meter::price_against`, lifted out of the metering step
so the step and the late reading call the same arithmetic). A second spelling of that
arithmetic is how one unit ends up settling two different amounts on two books.

One ordering detail carries the whole case. The wrapper's `Drop` lets the **inner body go
first** and only then fires the arm, because the legacy partial report is filed from the
inner body's own `Drop`. Rust drops a value's fields *after* its `Drop::drop` runs, so an arm
that read the cell before dropping the inner body would read an empty one and post nothing
for a request the previous release charges for. The order is the fix.

### What was measured, and what could not be

The oracle drives the client and always drains, so there is **no client-hangup cell** to
record. What the oracle does hold is the other half of the same predicate, and it holds it
across every dialect pair: `llm|<in>|<out>|request|ok_stream` (a stream drained to its end →
billed) and `llm|<in>|<out>|request|stream_upstream_error` (a stream whose end carried a
terminal error → `billing_failed`, not billed), with `billing|key-usage|*` reading the spend
back off `/usage`. Those cells are byte-identical on this leg, which is what says the
predicate itself has not moved.

The hangup arm is the *same arm* as the cut arm — one `Drop`, one report, one gate — so a leg
that matches on the cut and reads the cell rather than deciding for itself cannot diverge on
the hangup. That is the argument, and it is why the code reads the cell instead of
reconstructing a figure of its own.

---

## 2. The in-flight slot and the hold

**Decision: the late accrual must not need either, and it does not.**

By the time the figure exists:

- the **hold** has left its cell. The exit is one of exactly two places a hold is taken out
  (the node's sweep is the other), and it consumed the hold by value to build the `Posted`.
- the **slot** has gone back to the table. `Occupied::drop` releases it on every way out of
  `answer` — the answer, a panic, and the client hanging up — and `answer` has returned by the
  time the body is handed to hyper.
- the **concurrency leases** have been released, or will be, on the sink's own schedule.

`Posted::settle_late` is built for exactly this: it takes a `HoldAccrual` and a `LedgerToken`
and nothing else. No cell, no parent, no slot, no `Usage`, no priced-nanos argument. It
re-checks nothing. It sets `reserved = 0` and `settled = overdraft = amount`, which is the
posting *saying*, in the two figures the reconciliation reads, that value moved with no
reservation behind it. That is not a defect being tolerated; it is an accurate description of
a spend the node learned about after it had let go.

Two consequences worth writing down.

**The sink cannot be held open to reach the figure.** A `UsageSink` carries the admission's
in-flight grant, whose `Drop` on the last clone releases the `concurrent` gauges. A clone kept
alive for the length of a response body would hold a deployment's concurrency leases open past
the moment the previous release releases them — an observable change, and one this seam is not
allowed to make. What is kept instead is the **card** (`CostHandle`): the one thing off the
sink a pricing needs, an opaque handle with no drop of its own, cloned at the door before the
walk takes the sink. It is the same card the admission pinned, so a request that opened before
a config reload is still priced on the rates it agreed to.

**The window is the unit's pinned arrival epoch, never a clock read at drain time.** A body
that drained past midnight would otherwise open a second day's row for a request the node
admitted, priced and billed in the first. Same balance, same window, same row.

---

## The row this lands on

`LateFigure` names the serving lane and its provider — the two names the legacy row is keyed
by — and the balance it posts to is keyed by principal and window. At the width a live node
keeps, those are the same row: the node's books retain no lane and no provider, so *both*
sides of the served reconciliation are read with those two names empty (see
`NodeLedger`'s `WIDTH_THE_NODE_KEEPS`). Carrying the names on the figure is what makes that a
fact about the width rather than a figure that lost its row on the way, and it is where a
wider key attaches the day the books grow one.

## Who prices it

Not this plane. The plane says what the unit **did**; the root says what it **cost**.

`Walk::reported_after_terminal` hands back a report and no money: the tier split the tap read,
by neutral unit class; the billable count the Meter step decided; and the serving lane and its
provider. There is no rate behind it, because a plane that could read a rate could price a
request, and a second place a rate lives is a second answer to what one request cost.

The composition root prices that report through `busbar_unit_cost::price`, against a `RateCard`
built at boot from the deployment's own `rate_card:` and `per_request_fee:` — the same two
configured figures the legacy `/usage` projection derives a row's spend from. The card is bound
onto the node beside the book (`bind_card`, beside `bind_book`), for the same reason: a node
that built its own would price traffic on rates nobody configured, and those figures would look
exactly like figures somebody did.

**The fee arrives by construction.** The cost unit's pricing is one line per reported quantity
*plus the flat fee as its own line*, at the card's configured fee times the count the report
carried, summed in before the single tier divide. So one call produces the token lines and the
fee line together, and there is no arm anywhere that could post the tokens and forget the fee.

The billable count is the plane's, unchanged: `delivered && upstream_leg` at the Meter step,
which is the same base the previous release charges the fee on — a refusal at the door, an
out-of-scope key and a failed transfer all report zero and are charged nothing. A stream whose
end carried a terminal error prices its TOKENS at zero and still carries its fee, because that
is exactly what the previous release bills for the same event: the fee was decided at the frame
that carried the status, and `finish_admitted` refunds only a non-2xx.

The identity is therefore an equality and not a difference:

```
Σ /ledger/totals priced_micros  ==  /usage total spend_micros
```

On the identity rig's four delivered completions that reads `10,120,000 == 10,120,000`, with
both halves pinned as absolutes so a change that moved the two sides identically still fails
rather than being absorbed.

---

## What did not move

`/usage` is byte-identical. The client's bytes are the client's bytes — the body wrapper
forwards every frame, in order, and answers the end-of-stream and size-hint questions by
asking the inner body. There is no new boot line, no new config key, no environment variable
and no new metrics series on a 1.5.5 configuration. The book the postings land on is
memory-buffered and reads no data directory, so nothing appears beside a configuration that
asked for none.
