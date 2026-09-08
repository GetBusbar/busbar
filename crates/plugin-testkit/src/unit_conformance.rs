// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Contract conformance for [`busbar_caps::Unit`] — the checks every unit crate must pass
//! identically.
//!
//! The `unit` row of `docs/design/PLUGIN-TREE.md` had no shared battery, because until
//! [`busbar_caps::Unit`] landed it had no trait for a battery to be written against. This module is
//! that battery, and it is deliberately the same SHAPE as [`crate::store_conformance`]: the helpers
//! live here once, each crate's own `tests/unit_conformance.rs` calls them, and a new ruling added
//! here reaches all fourteen crates on their next build instead of being hand-copied into fourteen
//! files and drifting.
//!
//! # The four rules, and why each is checked the way it is
//!
//! 1. **Every input is answered.** A unit hands back a `Decision` — a proceed or a refusal — for
//!    every input of its step. Never an `Option`, never a `Result` the caller has to interpret,
//!    never a silent no-op. Checked by calling and requiring a value back.
//! 2. **It never panics.** A panicking unit takes the whole loop down mid-flight, with a hold open
//!    and nothing settled. Checked with [`std::panic::catch_unwind`] around the call.
//! 3. **It never blocks.** `decide` is synchronous and is called on the loop's own thread; the ONE
//!    step the loop awaits (route) is awaited AROUND this call, never inside it. Checked as a wall
//!    bound on the call — a coarse instrument, and named as one: it catches a sleep, a lock held by
//!    another thread and a socket read, not a tight spin.
//! 4. **It never reads a wall clock.** A step that reads the clock cannot be replayed, so the time
//!    is an INPUT (`busbar-unit-auth`'s request struct carries `now: u64` for exactly this reason).
//!    Checked as determinism: the same input, twice, gives the same answer.
//!
//! Rule 3 is the only one that measures rather than proves, and rules 3 and 4 are both checked over
//! the SAME closure, so a unit that reads a clock to decide how long to block fails both.
//!
//! # Usage, from a unit crate's own `tests/unit_conformance.rs`
//!
//! ```ignore
//! use busbar_plugin_testkit::unit_conformance as conf;
//!
//! #[test]
//! fn the_step_this_unit_owns() {
//!     conf::assert_owns_one_step::<Scope>(StepName::Approve);
//! }
//!
//! #[test]
//! fn every_input_is_answered() {
//!     let seal = KernelSeal::acquire_for_kernel();
//!     let token = UnitToken::mint(&seal);
//!     conf::assert_answers(StepName::Approve, || unit.decide(&token, input()));
//! }
//! ```

use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

use busbar_caps::step::{Step, StepName};
use busbar_caps::{Decision, Unit};

/// The wall bound on one `decide` call. Generous on purpose: this is a check for a unit that
/// BLOCKS, not a benchmark, and a CI box under load must not turn a correct unit red.
pub const DECIDE_BUDGET: Duration = Duration::from_millis(250);

/// THE UNIT'S OWN STEP, stated once and cross-checked against the type that carries it.
///
/// Two assertions, not one: that the unit owns the step its author says it owns, and that its
/// `STEP` const still agrees with its `Step` type. The second cannot fail while `STEP` keeps its
/// derived default — and that is the point, because the day somebody overrides the default to
/// silence a placement bug, this is the check that names it.
pub fn assert_owns_one_step<U: Unit>(expected: StepName) {
    assert_eq!(
        U::STEP,
        expected,
        "a unit crate owns exactly one step of the loop, and this one does not own the step its \
         own conformance file names"
    );
    assert_eq!(
        U::STEP,
        <U::Step as Step>::NAME,
        "`Unit::STEP` disagrees with `Unit::Step`: the loop would place this unit at one step and \
         the token seal would admit it at another"
    );
}

/// EVERY INPUT IS ANSWERED, WITHOUT A PANIC, WITHOUT BLOCKING, AND WITHOUT A CLOCK.
///
/// `call` must perform exactly one `Unit::decide` over one input, and must be callable twice with
/// the same input — the second call is what makes reading a wall clock visible. `step` is the step
/// the answer must be stamped with.
pub fn assert_answers<S: Step>(step: StepName, call: impl Fn() -> Decision<S>) {
    let (first, elapsed) = timed_call(&call);
    assert!(
        elapsed <= DECIDE_BUDGET,
        "a unit's step took {elapsed:?}, over the {DECIDE_BUDGET:?} budget: `decide` is \
         synchronous and runs on the loop's own thread, so it may not block. (A coarse instrument: \
         it catches a sleep, a foreign lock and a socket read, not a tight spin.)"
    );
    let second = timed_call(&call).0;
    assert_eq!(
        first, second,
        "a unit answered the SAME input two different ways, so something outside the input decided \
         it — a wall clock, a global, or shared mutable state. The time a step reads is an input."
    );
    assert!(
        first.starts_with(&format!("Decision<{step}>")),
        "a unit's answer is stamped `{first}`, not with its own step `{step}`: the token it was \
         lent and the answer it built name two different steps"
    );
}

/// THE SAME FOUR RULES, for a unit that SERVES its step rather than owning it.
///
/// A serving unit's `Answer` is its own value — a priced posting, a sealed audit record, a journal
/// ack — so there is no step stamp to check and no `Decision` to render. `render` is the caller's
/// projection of the answer into something comparable; everything else is identical, deliberately,
/// because "never panics, never blocks, never reads a clock" is owed by both roles.
pub fn assert_total<R>(label: &str, call: impl Fn() -> R, render: impl Fn(&R) -> String) {
    let started = Instant::now();
    let first = std::panic::catch_unwind(AssertUnwindSafe(|| render(&call())))
        .unwrap_or_else(|_| panic!("{}", panicked(label)));
    let elapsed = started.elapsed();
    assert!(
        elapsed <= DECIDE_BUDGET,
        "`{label}` took {elapsed:?}, over the {DECIDE_BUDGET:?} budget: `decide` is synchronous and \
         runs on the loop's own thread, so it may not block."
    );
    let second = std::panic::catch_unwind(AssertUnwindSafe(|| render(&call())))
        .unwrap_or_else(|_| panic!("{}", panicked(label)));
    assert_eq!(
        first, second,
        "`{label}` answered the SAME input two different ways, so something outside the input \
         decided it — a wall clock, a global, or shared mutable state."
    );
}

/// The one sentence both roles fail with, so a reader meets it in one wording.
fn panicked(label: &str) -> String {
    format!(
        "`{label}` PANICKED on an input of its own step. A unit that panics takes the loop down \
         mid-flight, with a hold open and nothing settled; every input is answered instead."
    )
}

/// One `decide` call, rendered and timed, with a panic turned into the failure it is.
///
/// The rendering rather than the value, because `Decision` is deliberately not `Clone` and is read
/// only by the kernel — its `Debug` is the one thing a test outside the kernel may look at, and it
/// carries both arms and the step, which is all four rules need.
fn timed_call<S: Step>(call: &impl Fn() -> Decision<S>) -> (String, Duration) {
    let started = Instant::now();
    let answered = std::panic::catch_unwind(AssertUnwindSafe(|| format!("{:?}", call())));
    let elapsed = started.elapsed();
    match answered {
        Ok(rendered) => (rendered, elapsed),
        Err(_) => panic!("{}", panicked("a unit")),
    }
}
