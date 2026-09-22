// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S TELLER STEPS — one file per step, written dark behind `teller-waist`.
//!
//! The whole directory is gated by the inner attribute below rather than by a `#[cfg]` on each
//! `pub mod` line, so the flag is stated ONCE and "the flag is down" and "the directory is not in
//! the build" are the same fact. With the flag down this file is empty, the crate's dependency graph
//! is unchanged, and the legacy `native_ingress` path is the only path — which is what makes the
//! coexistence claim checkable rather than asserted.
//!
//! WHAT A STEP FILE IS. Each one holds the body of exactly one of the loop's steps for this plane,
//! typed the way the loop's step seam types it: a step is handed `&Pass<S>` for its OWN step
//! and answers with a `Decision<S>`, so it can neither answer a question it was not asked nor read
//! its own answer back. The type that implements that seam is the composition root's, not this
//! crate's — these are the per-step bodies it delegates to, which is why nothing here names the
//! kernel crate and nothing here mints a token.
//!
//! WHAT A STEP FILE IS NOT. It is not a renderer. A step names its refusal — status, kind word,
//! message — and the audit step is the one place in this directory that turns a named refusal into
//! bytes. That is the rule that keeps every terminal on this plane on one path.
//!
//! GATING. Every step file below is compiled only behind `teller-waist` — with the flag down the
//! step machinery is not in the build and the legacy `native_ingress` path is the only path. The one
//! exception is [`audit`]: it is declared unconditionally because the plane's terminal DOORS are
//! spelled there and nowhere else (the construction gate names its file), and the legacy path — which
//! compiles WITHOUT `teller-waist` — reaches them through the neutral pass-throughs the file exposes.
//! Only `audit`'s NEUTRAL half (the refusal value, the renderer, the sealed-bytes newtype and the two
//! door pass-throughs) compiles with the flag down; its step-typed half (the audit steps proper and
//! the capability vocabulary they are written in) stays behind `teller-waist`, so the dependency
//! graph with the flag down is unchanged.

/// Step 4 — the charge: the admission door, then the hold and the meter half it opens.
#[cfg(feature = "teller-waist")]
pub mod admit;
/// Step 3 — whether the caller may do this at all: the one native veto seat, which nothing
/// installs today. The migrated hooks are NOT seated here — they fire after the door on the live
/// path, and a hook that runs after a charge cannot veto before one.
#[cfg(feature = "teller-waist")]
pub mod approve;
/// Step 0 — what arrived: the body read and the path-carried model splice.
#[cfg(feature = "teller-waist")]
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
pub(crate) use audit::{
    finish_admitted_via_audit, finish_rejected_via_audit, finish_rejected_via_audit_arrival,
    render_refusal, RefusalOutcome,
};
/// Step 1 — who is calling: the read of the auth middleware's already-resolved outcome.
#[cfg(feature = "teller-waist")]
pub mod authenticate;
/// The flip's rehearsal — one request driven through every step below, in order, against the
/// legacy plane on the same fixtures. Tests only.
#[cfg(feature = "teller-waist")]
pub mod chain;
/// Step 1 — what it means: the model ladder and the handler lookup, in both live orders.
#[cfg(feature = "teller-waist")]
pub mod decode;
/// Step 6 — the figures: the one metering seam, the fee and the refund decided by the outcome.
#[cfg(feature = "teller-waist")]
pub mod meter;
/// Step 5 — the one attempt: candidates, the pick, the walk, the completion tap.
#[cfg(feature = "teller-waist")]
pub mod route;
/// Step 2 — where the unit may go: the three pre-admission guards, in their one order.
#[cfg(feature = "teller-waist")]
pub mod verify;
/// The carry between the steps, and the runtime seam the walk is run across. Not a step, and not a
/// driver: the composition root drives, and this is what it drives the two engine-typed steps
/// through.
#[cfg(feature = "teller-waist")]
pub mod walk;
