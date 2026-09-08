// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT'S PER-UNIT JOURNAL — the one thing a running binary emits that tells an outside
//! observer WHICH HALF OF THE BINARY ANSWERED a served request.
//!
//! ## Why this exists
//!
//! `qa/teller-steps.json` makes a claim per plane about the shipped path: whether a request that
//! arrives on the wire is answered by the kernel loop in this composition root or by the legacy
//! plane crate the root was built to replace. Until this module, nothing the binary emitted could
//! settle that question from outside. The switch is a Cargo feature resolved at compile time, both
//! halves end on the same `busbar_core::ingress` terminal, both are scraped through the same
//! `/metrics` families, neither writes an audit record on the data plane, and no response header
//! distinguishes them — a build with the loop on and a build with it off answer a client
//! identically, on purpose. So the matrix asserted something no gate could measure, which is the
//! one thing a gate may never do.
//!
//! This module is the missing measurement, and it is deliberately the SMALLEST thing that can be
//! one: a `DEBUG`-level record, per unit, naming the leg and which half produced the answer.
//!
//! ## Why a DEBUG record and not a metric
//!
//! Every alternative moves something a released contract has already pinned. A new `/metrics`
//! family changes the exposition's `# HELP`/`# TYPE` set, which the shadow oracle records
//! byte-for-byte on a 1.5.5-shaped config; a `busbar_plane_*`-prefixed name additionally trips the
//! absence contract that says no plane series may appear just because the binary can compile one
//! in; a response header is refused by `cargo xtask gate response-header` unless it is an opt-in
//! toggle, and an opt-in toggle is a thing an operator can turn off, which makes the measurement
//! optional. `INFO` and above is pinned by the boot-line neutrality contract. `DEBUG` is pinned by
//! nothing, is off in every recorded configuration, costs one filtered call per unit when it is
//! off, and is exactly the verbosity at which "which code path did this request take" is the
//! question an operator is asking.
//!
//! ## What a reader may conclude
//!
//! One record is emitted per unit the root drives through `busbar_kernel::teller::run_unit` /
//! `run_unit_async` ([`Answered::Loop`]), and one per request the root hands BACK to the legacy
//! router to answer ([`Answered::Legacy`]). A leg that emits neither for a request it was sent is a
//! leg the root took no part in; that is not an omission here, it is the finding.
//!
//! The absence of a record is only meaningful when the mechanism is known to work, so the reader —
//! `cargo xtask gate teller-steps` — refuses a probe run in which NO leg emitted a record at all
//! rather than reading a broken instrument as five legacy legs.

/// Which half of the binary produced the answer bytes for one served request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answered {
    /// The kernel loop in this composition root ran the unit and its terminal produced the answer.
    Loop,
    /// The root handed the request back to the legacy router, which re-served it and produced the
    /// answer bytes. The root may still have GATED the request — that is what makes a leg split
    /// rather than legacy — but these bytes are not the loop's.
    Legacy,
}

impl Answered {
    /// The word the record carries, and the word the gate's reader matches on. A wire-visible name
    /// written once.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Answered::Loop => "loop",
            Answered::Legacy => "legacy",
        }
    }
}

/// The tracing target every record carries, so a reader can select these lines and nothing else.
pub const TARGET: &str = "busbar::root::journal";

/// The record's message. Constant because it is what an external reader greps for, and a message
/// written twice is a message that can be written two ways.
pub const MESSAGE: &str = "root served unit";

/// The leg names, which are the plane names the Teller-step matrix rows are keyed by.
pub mod leg {
    pub const ADMIN: &str = "admin";
    pub const LLM: &str = "llm";
}

/// Emit one journal record: this leg served one unit, and this half of the binary answered it.
pub fn served(leg: &'static str, answered: Answered) {
    tracing::debug!(
        target: TARGET,
        leg = leg,
        answered = answered.word(),
        "{MESSAGE}"
    );
}

#[cfg(test)]
#[path = "tests/journal.rs"]
mod tests;
