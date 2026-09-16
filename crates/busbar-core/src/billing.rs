// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Polymorphic billable-item data model.
//!
//! The billable UNIT is operation-dependent: some operations meter tokens, others meter a duration, a
//! character count, or a per-item count, and some carry no meter at all. A single fixed struct cannot
//! represent that, so [`Billing`] is a closed enum every `OperationHandler` emits from a response (or
//! computes from request params when the upstream returns no usage object).
//!
//! The type DEFINITIONS ([`TokenUsage`], [`Billing`]) RELOCATED to `busbar-substrate`
//! (`busbar_substrate::billing`) at Batch C-0 — pure data naming zero core type, so a plane crate
//! names them without reaching into `busbar-core`. Core re-exports both from this
//! historical path so every in-core and plugin caller (`crate::billing::Billing`) compiles unchanged.

pub use busbar_substrate::billing::{Billing, TokenUsage};

#[cfg(test)]
#[path = "tests/billing_tests.rs"]
mod tests;
