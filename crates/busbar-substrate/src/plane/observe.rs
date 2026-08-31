// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL plane-observe response marker.
//!
//! [`Counted`] is the one type the plane-observe boundary and a plane's own handler both name: the
//! handler inserts it on a response it has already labelled, and core's `plane::observe` middleware
//! reads it to stand down. It carries nothing and names no engine type, so it lives here in the
//! neutral substrate — a plane crate marks a response (`busbar_substrate::plane::observe::Counted`)
//! without reaching into `busbar-core`, and core re-exports it so its own middleware reads the SAME
//! type it did before.

/// A MARKER A PLANE'S HANDLER PUTS ON A RESPONSE IT HAS ALREADY LABELLED.
///
/// It carries nothing, and carrying nothing is the point: this is not a channel for the handler to
/// pass its labels up through, which would put the emit back in one place and the label vocabulary
/// in another. The handler emits its own series with the binding only it knows, and this says so, so
/// core's `plane::observe` can cover exactly the requests no handler saw without counting anything
/// twice.
///
/// A response extension rather than a request one, because the answer is what carries the fact and
/// the boundary reads it after the handler has run.
#[derive(Clone, Copy)]
pub struct Counted;
