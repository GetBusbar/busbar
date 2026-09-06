# Kernel group leases — the door names the groups, the slot counts them

`ARCHITECTURE.md` v1.31 §2.2, Admit: *"A `concurrent` lease per capped-`concurrent` bucket"*, and the
exit path: *"the same CAS releases the unit's `concurrent` leases (every end)"*. Plural, per group.

## What is here today

The door's yes draws **one** lease, node-wide: `IN_FLIGHT` (`kernel:in_flight`), recorded on the
unit's slot by `draw_lease` in `busbar-kernel/src/teller.rs` and given back by whichever of the
unit's two ends arrives first. The per-group counts exist, but only on the door's own `Gauges` in
`busbar-unit-admission`, held by an `AdmitGrant` that lives no longer than the `Units::admit` call.
So the node has a reading of how many units it is running and no reading at all of how many are
running *in each capped group* — and nothing outside the door can be told, because the door's group
names are config-derived `String`s while `BucketId.id` is a `&'static str`.

## The seam

Three small pieces, no new workspace dependency for the door (it keeps its one, `busbar-caps`):

1. **The root interns group names.** `ConfigKeys` gains `groups`, so every configured group name
   becomes a `&'static str` exactly once at boot, through the same `busbar_contract::Registration`
   that already interns lanes, pools, models and bucket windows.
2. **The door carries the static name it was handed.** `GroupRuntime` and `ChainGroup` gain
   `lease_id: Option<&'static str>` — set by the composition root at registration, `None` where no
   name was interned. `AdmitGrant` records the `lease_id` of every group whose concurrent gauge it
   counted, and `AdmissionUnit::group_leases()` reads them back, the same read-back shape as
   `blocked()` and `parent_accrual_refused()`.
3. **The kernel records them on the slot.** `Units::admit` is lent a `GroupLeaseSlip` — a kernel type,
   created per unit on the loop's own frame — which the door's adapter fills with what it counted.
   `draw_lease` then takes `IN_FLIGHT` *and* one `BucketId` per named group onto the unit's
   `LeaseCell`, so the slot owns them all and `LeaseCell::release_all` gives them all back at
   whichever end arrives first. The per-group gauge reads `ConcurrencyGauge::count`.

The slip goes through the trait rather than through `busbar-caps` deliberately: the capability crate
is at its surface ceiling, and a value that exists only between the door's answer and the next line
of the loop is not a capability — it is an out-parameter, and it reads as one.

## Why it is safe

**The door still decides; the kernel only counts.** The slip is written *after* the decision and is
never read by it, and `ConcurrencyGauge::record` is the counting entry point that cannot refuse —
`acquire` (which can) is not on this path. A group with no interned name records nothing, which is
exactly today's behaviour. Nothing here can turn a yes into a no, so refusals, statuses, usage rows
and retry hints are the ones 1.5.5 renders, byte for byte.

## What it does not change

The admission decision function; the door's own `Gauges` and their cap check; `IN_FLIGHT` and its
node-wide meaning; the exit path and the sweep, which already release whatever the slot holds; the
`Admission`/`Decision` shapes in `busbar-caps`; the ledger, the hold, the slices and the windows.
Exempt origins stay exempt: a handshake, a tick and a kernel-verb unit draw no lease of either kind,
so an operator's surface still answers while a group is capped out.
