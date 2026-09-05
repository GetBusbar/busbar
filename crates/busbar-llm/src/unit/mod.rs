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
//! typed the way the loop's step seam types it: a step is handed `&UnitToken<S>` for its OWN step
//! and answers with a `Decision<S>`, so it can neither answer a question it was not asked nor read
//! its own answer back. The type that implements that seam is the composition root's, not this
//! crate's — these are the per-step bodies it delegates to, which is why nothing here names the
//! kernel crate and nothing here mints a token.
//!
//! WHAT A STEP FILE IS NOT. It is not a renderer. A step names its refusal — status, kind word,
//! message — and the audit step is the one place in this directory that turns a named refusal into
//! bytes. That is the rule that keeps every terminal on this plane on one path.

#![cfg(feature = "teller-waist")]

/// Step 1 — who is calling: the read of the auth middleware's already-resolved outcome.
pub mod authenticate;

/// Step 2 — where the unit may go: the three pre-admission guards, in their one order.
pub mod verify;

/// Step 3 — whether the caller may do this at all: the migrated hook seats' veto.
pub mod approve;
