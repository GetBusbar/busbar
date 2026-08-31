// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Polymorphic billable-item data model.
//!
//! The billable UNIT is (operation, model)-dependent: chat/embeddings bill tokens, `whisper-1` bills
//! audio DURATION, `tts-1` bills CHARACTERS, dall-e bills per IMAGE. A single fixed struct cannot
//! represent that, so [`Billing`] is a closed enum every `OperationHandler` emits from a response (or
//! computes from request params when the provider returns no usage object).
//!
//! The type DEFINITIONS ([`TokenUsage`], [`Billing`]) RELOCATED to `busbar-substrate`
//! (`busbar_substrate::billing`) at Batch C-0 — pure data naming zero core type, so a plane crate
//! (`busbar-mcp`) names them without reaching into `busbar-core`. Core re-exports both from this
//! historical path so every in-core and plugin caller (`crate::billing::Billing`) compiles unchanged.

pub use busbar_substrate::billing::{Billing, TokenUsage};

#[cfg(test)]
#[path = "tests/billing_tests.rs"]
mod tests;
