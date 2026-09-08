// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The view types the admin control surface answers money in.
//!
//! ## Why these live here and not beside the surface that serves them
//!
//! The admin surface is a CONTROL surface, and the rule it is built to is that it names no figure:
//! no money type, no currency, no amount identifier appears in it. But five of its verbs answer
//! with figures, and those figures need a shape. Putting the shape here is what lets the surface
//! pass bytes through without ever holding a number it could round, re-derive or re-order.
//!
//! ## What a view is, and what it is not
//!
//! A view is a SHAPE and a rendering. It holds figures somebody else computed and it knows how to
//! write them down. It computes nothing: there is no arithmetic in this module beyond the one
//! subtraction that a residual IS, and every constructor takes its figures already made. The
//! identity's own arithmetic lives in `busbar-unit-ledger`, which is where the terms are defined
//! and where the checkpoint that anchors them is sealed.
//!
//! That division is deliberate and load-bearing: if a view could compute, then two callers
//! rendering the same balance could disagree, and the disagreement would be invisible because both
//! answers would look like the ledger's.
//!
//! ## Every amount is a decimal STRING on the wire
//!
//! Nano-units are `i128`. JSON numbers are doubles in most consumers, and a double loses integers
//! above 2^53 — which for nano-units is about nine million currency units, a figure a real
//! deployment passes. So every amount renders as a quoted decimal string, and a consumer that
//! wants a number has to say so by parsing one. A silently-rounded invoice is worse than a
//! rejected one.

use core::fmt::Write as _;

/// One balance's raw figures, in the identity's own terms, at one instant.
///
/// A carrier, so a caller can hand over a snapshot without this crate naming the ledger's `Totals`
/// (which lives in a crate this one does not, and must not, depend on). Every field is a running
/// figure in nano-units as the books hold it — nothing here is a delta.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdentityTerms {
    /// How much has actually been posted.
    pub settled: i128,
    /// How much is reserved against holds that have not closed.
    pub open_holds: i128,
    /// How much sits in slices drawn but not yet spent or released.
    pub open_slice_remainders: i128,
    /// How much has been posted that the recompute has not yet agreed with.
    pub unreconciled: i128,
    /// How much has been moved by a correction, positive or negative.
    pub adjustments: i128,
    /// Overdraft carried OUT less overdraft carried IN, as the books hold the pair.
    pub overdraft_carried: i128,
    /// Value that has crossed this window's boundary: out, less in.
    pub cross_window_transfers: i128,
    /// How much has been taken out of the store.
    pub drawn: i128,
}

/// One balance's identity, as a change since the last sealed checkpoint.
///
/// The eight terms are the identity's own, in the order it states them:
///
/// ```text
///   Δ settlements + Δ open holds + Δ open-slice remainders + Δ unreconciled
/// + Δ adjustments − Δ overdraft carried ± Δ cross-window transfers
/// = Δ drawn from the store
/// ```
///
/// `residual_nanos` is the left-hand side minus the right, and `closes` is that residual being
/// zero. Both are carried rather than left to the reader to derive: a consumer that recomputed the
/// residual from the terms would be a second implementation of the identity, and the whole point of
/// serving it is that there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDeltaView {
    /// Which pot.
    pub bucket: String,
    /// Counting what.
    pub dimension: String,
    /// How wide.
    pub scope: String,
    /// The window this balance is measured in, as a unix second.
    pub window_start: u64,
    /// Δ settlements.
    pub delta_settlements: i128,
    /// Δ open holds.
    pub delta_open_holds: i128,
    /// Δ open-slice remainders.
    pub delta_open_slice_remainders: i128,
    /// Δ unreconciled.
    pub delta_unreconciled: i128,
    /// Δ adjustments.
    pub delta_adjustments: i128,
    /// Δ overdraft carried — SUBTRACTED by the identity, and carried here with the sign it has in
    /// the books rather than pre-negated, so a reader can check the arithmetic as it is written.
    pub delta_overdraft_carried: i128,
    /// Δ cross-window transfers.
    pub delta_cross_window_transfers: i128,
    /// Δ drawn from the store — the right-hand side.
    pub delta_drawn: i128,
    /// Left-hand side minus right-hand side. Zero is the only good answer.
    pub residual_nanos: i128,
    /// Whether the identity closes for this balance.
    pub closes: bool,
}

impl IdentityDeltaView {
    /// The identity for one balance, as the change between two snapshots of it.
    ///
    /// `since` is the last sealed checkpoint's figures; `now` is the figures as they stand. A key
    /// absent from the checkpoint is measured from zeros, which is right: it held nothing then.
    ///
    /// **This is a second statement of the identity, and it is checked against the first.** The
    /// authoritative one is `busbar_unit_ledger::identity::residual`, which is where the terms are
    /// defined and where a checkpoint anchors them. This one exists because the view has to render
    /// each term's delta anyway, and deriving the residual from the same subtractions it is already
    /// making is cheaper and clearer than carrying a number computed somewhere else beside them. A
    /// cross-crate agreement test in the composition root asserts the two answers are equal over
    /// random figures, so the pair cannot drift apart in silence.
    #[allow(clippy::too_many_arguments)]
    pub fn between(
        bucket: impl Into<String>,
        dimension: impl Into<String>,
        scope: impl Into<String>,
        window_start: u64,
        since: &IdentityTerms,
        now: &IdentityTerms,
    ) -> Self {
        let delta_settlements = now.settled - since.settled;
        let delta_open_holds = now.open_holds - since.open_holds;
        let delta_open_slice_remainders = now.open_slice_remainders - since.open_slice_remainders;
        let delta_unreconciled = now.unreconciled - since.unreconciled;
        let delta_adjustments = now.adjustments - since.adjustments;
        let delta_overdraft_carried = now.overdraft_carried - since.overdraft_carried;
        let delta_cross_window_transfers =
            now.cross_window_transfers - since.cross_window_transfers;
        let delta_drawn = now.drawn - since.drawn;
        // The identity, term for term and in its own order. Overdraft is SUBTRACTED; everything
        // else adds.
        let accounted = delta_settlements
            + delta_open_holds
            + delta_open_slice_remainders
            + delta_unreconciled
            + delta_adjustments
            - delta_overdraft_carried
            + delta_cross_window_transfers;
        let residual_nanos = accounted - delta_drawn;
        IdentityDeltaView {
            bucket: bucket.into(),
            dimension: dimension.into(),
            scope: scope.into(),
            window_start,
            delta_settlements,
            delta_open_holds,
            delta_open_slice_remainders,
            delta_unreconciled,
            delta_adjustments,
            delta_overdraft_carried,
            delta_cross_window_transfers,
            delta_drawn,
            residual_nanos,
            closes: residual_nanos == 0,
        }
    }

    /// Render this view as a JSON object.
    ///
    /// Hand-written rather than derived, for the reason the crate doc gives about dependencies:
    /// this crate carries no serializer, and acquiring one to render eleven fields would put a
    /// derive macro between an auditor and the bytes an invoice is read from.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"bucket\":");
        json_string(&self.bucket, &mut out);
        out.push_str(",\"dimension\":");
        json_string(&self.dimension, &mut out);
        out.push_str(",\"scope\":");
        json_string(&self.scope, &mut out);
        let _ = write!(out, ",\"window_start\":{}", self.window_start);
        for (name, amount) in [
            ("delta_settlements", self.delta_settlements),
            ("delta_open_holds", self.delta_open_holds),
            (
                "delta_open_slice_remainders",
                self.delta_open_slice_remainders,
            ),
            ("delta_unreconciled", self.delta_unreconciled),
            ("delta_adjustments", self.delta_adjustments),
            ("delta_overdraft_carried", self.delta_overdraft_carried),
            (
                "delta_cross_window_transfers",
                self.delta_cross_window_transfers,
            ),
            ("delta_drawn", self.delta_drawn),
            ("residual_nanos", self.residual_nanos),
        ] {
            let _ = write!(out, ",\"{name}\":\"{amount}\"");
        }
        let _ = write!(out, ",\"closes\":{}", self.closes);
        out.push('}');
        out
    }
}

/// Write one JSON string literal, escaping what the grammar requires and nothing else.
///
/// A bucket name reaches this from configuration, so it is not this module's to assume well-formed.
/// The escape set is JSON's own minimum: the two structural characters and the C0 controls.
fn json_string(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
#[path = "tests/view_tests.rs"]
mod tests;
