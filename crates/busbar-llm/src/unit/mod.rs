// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S TELLER STEPS — one file per step, and LIVE: every request on this plane is a
//! unit ([`node`](crate::unit::node)) the composition root's node drives through the kernel's loop over these files.
//! There is no other path for an arrival to take — the shell the steps replaced survives only as
//! the test kit's witness leg (ARCHITECT R7(b): the node-off build path is dropped).
//!
//! WHAT A STEP FILE IS. Each one holds the body of exactly one of the loop's steps for this plane,
//! typed the way the loop's step seam types it: a step is handed `&Pass<S>` for its OWN step
//! and answers with a `Decision<S>`, so it can neither answer a question it was not asked nor read
//! its own answer back. The type that implements that seam is [`node`](crate::unit::node)'s unit — the one file here
//! that names the kernel's loop — and these are the per-step bodies it delegates to, which is why no
//! step file names the kernel crate and nothing here mints a token.
//!
//! WHAT A STEP FILE IS NOT. It is not a renderer. A step names its refusal — status, kind word,
//! message — and the audit step is the one place in this directory that turns a named refusal into
//! bytes. That is the rule that keeps every terminal on this plane on one path.
//!
//! NO GATE. The files compile in every build of this crate; no feature keeps them dark.

/// Step 4 — the charge: the admission door, then the hold and the meter half it opens.
pub mod admit;
/// Step 3 — whether the caller may do this at all: the one native veto seat, which nothing
/// installs today. The migrated hooks are NOT seated here — they fire after the door on the live
/// path, and a hook that runs after a charge cannot veto before one.
pub mod approve;
/// Step 0 — what arrived: the body read and the path-carried model splice.
pub mod arrival;
/// Step 7 — the two terminal doors, and nothing else. Declared unconditionally: its neutral half
/// (the door pass-throughs + refusal renderer) is what the legacy path posts through with the waist
/// down, and the construction gate names this file as the plane's one door-call site.
pub mod audit;

// The terminal's NEUTRAL half, re-exported one level up so the legacy paths (`arrival`,
// `native_ingress`) can name the door pass-throughs and the refusal renderer as `crate::unit::_`
// rather than by the audit step's own module path at every call — the kind-isolation matrix counts
// that path as this plane growing its coupling to the teller steps, so a plane naming its own steps
// by the module path would grow that coupling on every site. The items themselves are unconditional
// (the legacy path compiles with the waist down); this re-export is too.
pub(crate) use audit::{finish_admitted_via_audit, RefusalOutcome};
// The rejected doors and the renderer are named one level up by the test kit's witness leg alone:
// the loop's own arrivals post through the audit step by its module path.
#[cfg(any(test, feature = "test-support"))]
pub(crate) use audit::{
    finish_rejected_via_audit, finish_rejected_via_audit_arrival, render_refusal,
};
/// Step 1 — who is calling: the read of the auth middleware's already-resolved outcome.
pub mod authenticate;
/// The flip's rehearsal — one request driven through every step below, in order, against the
/// legacy plane on the same fixtures. Tests only.
pub mod chain;
/// Step 1 — what it means: the model ladder and the handler lookup, in both live orders.
pub mod decode;
/// Step 6 — the figures: the one metering seam and the fee decided by the outcome. The refund is the
/// admitted terminal door's (step 7), not this step's.
pub mod meter;
/// The unit the composition root's node drives — the ten methods over the step files below — and the
/// body- and path-model arrivals that hand it to the node.
pub mod node;
/// Step 5 — the one attempt: candidates, the pick, the walk, the completion tap.
pub mod route;
/// Step 2 — where the unit may go: the three pre-admission guards, in their one order.
pub mod verify;
/// The carry between the steps, and the runtime seam the walk is run across. Not a step, and not a
/// driver: the composition root drives, and this is what it drives the two engine-typed steps
/// through.
pub mod walk;
