<!--
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2026 Busbar Inc and contributors
-->

# The durable-handle engine's retention sweep — what it costs, and what a redesign may not change

`crates/busbar-substrate/src/plane/handle_engine.rs`

## The shape today

`DurableHandleEngine::submit` takes the engine's OUTER lock — the one guarding the
`HashMap<String, Arc<Mutex<HandleSlot>>>` working set — and, while holding it, runs
`sweep_locked` before inserting the new handle. `sweep_locked` applies three rules in order:

0. **Abandon.** Every ACTIVE handle idle longer than `abandon_secs` is handed to the plane's
   `abandon` callback, and the mutation it returns is applied — a durable row upsert, an event
   append, or both.
1. **TTL evict.** Every TERMINAL handle older than `terminal_ttl_secs` is removed.
2. **Cap evict.** If the set is still at or over `max_retained`, the oldest TERMINAL handles are
   removed until it is under. **An ACTIVE handle is never removed to make room.**

Each rule opens with a FULL SCAN of the map, taking every handle's inner lock in turn to read its
`meta`. That is three O(n) passes, on every submit, under a lock that every other submit and every
map lookup has to wait behind. Rule 0's durable I/O happens inside that window — the module header
already flags this as the one place where the outer lock is held across a store round-trip.

Two consequences, and the second is the one that turns a cost into a cliff:

- **The scan is unconditional.** A steady-state deployment whose handles are all fresh and all
  active pays three full passes per submit to discover, three times, that there is nothing to do.
- **`max_retained` does not bound the working set.** Rule 2 evicts only TERMINAL handles, so when
  nothing is terminal there is nothing it may drop. A burst of concurrent active handles carries the
  set arbitrarily far past `max_retained`, and every subsequent submit's three passes get longer.
  The cost of the sweep grows with exactly the condition the sweep exists to relieve.

That second point is a defect of DESCRIPTION as much as of mechanism: `SweepBounds::max_retained` is
documented as "the hard ceiling on working-set entries", and it is not a ceiling. It is a ceiling on
the terminal population. The behaviour is right — dropping a live handle is forgetting work that is
still running, which is worse than holding memory — and the word "hard ceiling" is what is wrong.

## What a redesign must not change

`the_sweep_keeps_every_active_handle_and_evicts_terminal_ones_oldest_first`
(`crates/busbar-substrate/src/plane/tests/handle_engine_tests.rs`) pins the observable outcome
BEFORE the mechanism moves. Four facts, each of which a plausible redesign could quietly alter:

1. An ACTIVE handle is never evicted. The working set goes over `max_retained` and stays there.
2. A handle idle past `abandon_secs` is SETTLED by the plane's callback, not dropped.
3. The rules run in ORDER within one sweep, and the order is the outcome: abandon settles a handle,
   which makes it terminal, which makes it eligible for the cap rule IN THE SAME PASS. A handle can
   be abandoned and evicted by one submit.
4. Eviction is oldest-first on `updated_at`, with the handle id as the tie-break — which is what a
   sort over `(updated_at, id)` gives, and what an insertion-ordered or arrival-ordered index would
   NOT give when a batch of handles is abandoned at one `now` and so all carry the same timestamp.

Nothing sweeps on a read, and nothing sweeps on a timer. Every rule fires from a submit.

## The shape proposed

Three changes, independent of each other, smallest first:

1. **Lift the abandon writes out of the outer lock.** Rule 0 already collects its candidate ids into
   a `Vec` before acting on them. Collect the `(id, Arc<Mutex<HandleSlot>>)` pairs, RELEASE the outer
   lock, apply the mutations against the per-handle inner locks (which is the discipline every other
   write path already follows), then re-take the outer lock for rules 1 and 2. The inner lock is what
   serializes a handle's chain, so correctness does not depend on the outer one being held; what
   changes is that a slow store no longer blocks every submit in the process. The re-entry has to
   re-read each slot's `meta` rather than trusting the values read before the gap, because a
   concurrent `mutate` may have settled or touched the handle in between — and that is precisely the
   case where the abandon must NOT fire.

2. **A time-ordered expiry index.** Keep a `BTreeMap<(u64 /* updated_at */, String /* id */), ()>`
   beside the map, maintained on insert / remove / meta-change. Every rule then reads a PREFIX of it
   rather than scanning: rule 0 takes the range below `now - abandon_secs` and stops at the first
   entry that is not due, rule 1 the same against `terminal_ttl_secs`, rule 2 takes from the front.
   The sort key is `(updated_at, id)` — deliberately the same total order the current
   `sort_unstable` over a `Vec<(u64, String)>` produces, which is how fact 4 above survives the move.
   The index must be updated by `apply_mutation_to_slot`, because that is the one place `updated_at`
   changes; a handle whose key is stale is a handle the sweep will consider at the wrong age.

3. **An amortised trigger.** Even a prefix read is a lock acquisition per submit. Keep a
   `last_swept: AtomicU64` and run the sweep only when `now` has advanced past it by some floor (one
   second is enough — every bound is in whole seconds, so a sweep twice in one second cannot reach a
   different verdict). A submit that skips the sweep still INSERTS, so the working set is never
   stale in the direction that matters. This preserves fact 4's "nothing sweeps on a timer": the
   trigger is still a submit, it is just not every submit.

Steps 2 and 3 compose: with the index, the sweep is O(evicted) rather than O(n); with the trigger,
it is amortised over a second's worth of submits. Step 1 is worth landing on its own — it is the one
that removes durable I/O from under a process-wide lock, and it does not depend on either other.

## What is NOT proposed

Making `max_retained` a true ceiling by evicting active handles. That would be forgetting live work
to satisfy a number, and no caller can distinguish an evicted active handle from one that never
existed — the read path answers both with the same indistinguishable denial. If a deployment needs a
real bound on concurrent live handles, the place for it is ADMISSION (refuse the submit) and not
retention (silently drop the accepted); a refusal is a fact the caller can act on and an eviction is
not. Until then, `max_retained`'s doc comment should say what it bounds: the TERMINAL population,
and the working set only insofar as handles settle.
