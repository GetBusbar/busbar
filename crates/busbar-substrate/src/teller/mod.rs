// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TELLER — the one governed request loop every protocol plane rides, expressed as nine named
//! steps whose ORDER is fixed by types rather than by discipline.
//!
//! A unit is one governed transaction: it arrives, is decoded, authenticated, verified against its
//! destination, approved, admitted (which opens a [`Hold`]), routed, metered and finally audited,
//! which posts the unit ([`Posted`]). The loop in [`run_unit`] is the only place that sequence is
//! written down; a plane contributes one method per step ([`TellerPlane`]) and can neither reorder
//! the steps nor skip one, because each step's method is handed a [`UnitToken`] for exactly that
//! step and must answer with a [`Decision`] for exactly that step — and only the loop can mint a
//! token.
//!
//! Neutral by construction: nothing here names a plane, a dialect or a wire format. The plane's own
//! facts (its parsed body, its handler, its engine) stay on the plane value; the loop threads only
//! the small neutral facts each step hands the next.
//!
//! Layout:
//! - [`tokens`] — the capability types (`UnitToken<S>`, `Decision<S>`, `Hold`, `Posted`);
//! - [`steps`] — the `TellerPlane` trait (one method per step), `Refusal` and the step facts;
//! - [`unit`] — the per-unit neutral facts (`Unit`), `UnitEnd` and `StepName`;
//! - `run` — the loop itself (`run_unit`, plus `open_unit` for a session opener that has no Route leg).

mod run;
pub mod steps;
pub mod tokens;
pub mod unit;

pub use run::{open_unit, run_unit};
pub use steps::{Closing, Metered, Principal, Refusal, TellerPlane};
pub use tokens::{Decision, Hold, Posted, UnitToken};
pub use unit::{StepName, Unit, UnitEnd};

/// The seal on [`Step`]: only the nine markers declared in this module can implement it, so no
/// plane can invent a tenth step or a private marker that would let it mint tokens of its own.
mod sealed {
    pub trait Sealed {}
}

/// One of the nine Teller steps, as a zero-sized type-level marker. `Facts` is the neutral value a
/// `Decision::proceed` for this step carries forward to the next step; `NAME` is the same step as
/// a plain runtime value for audit rows and refusals.
pub trait Step: sealed::Sealed + Send + Sync + 'static {
    /// What a successful pass through this step hands the next step.
    type Facts: Send;
    /// The step as a runtime name.
    const NAME: StepName;
}

macro_rules! step_marker {
    ($(#[$doc:meta])* $name:ident, $facts:ty) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl Step for $name {
            type Facts = $facts;
            const NAME: StepName = StepName::$name;
        }
    };
}

step_marker!(
    /// Step 1 — the bytes arrived and the transport-level arrival facts were read. The kernel's
    /// arrival work ran before the loop; this step is where the plane reads its share of it.
    Arrival,
    ()
);
step_marker!(
    /// Step 2 — the plane recognised the request's shape (its handler, its operation, its target).
    Decode,
    ()
);
step_marker!(
    /// Step 3 — the caller identity is resolved (the auth layer already ran; this step reads it).
    Authenticate,
    Principal
);
step_marker!(
    /// Step 4 — the destination is verified against the caller's scope BEFORE anything is charged.
    Verify,
    ()
);
step_marker!(
    /// Step 5 — the approval seat (a pass-through today; migrated hooks seat after Admit).
    Approve,
    ()
);
step_marker!(
    /// Step 6 — admission: the budget/concurrency door. A pass opens the unit's [`Hold`].
    Admit,
    Hold
);
step_marker!(
    /// Step 7 — the plane's engine routes the unit and produces the (possibly streaming) response.
    Route,
    axum::response::Response
);
step_marker!(
    /// Step 8 — the meter reads what the routed response cost, for Audit to post.
    Meter,
    Metered
);
step_marker!(
    /// Step 9 — the terminal: the plane finishes the unit and hands back the one response the loop
    /// returns. The loop mints [`Posted`] from this step's token, and only from it.
    Audit,
    axum::response::Response
);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
