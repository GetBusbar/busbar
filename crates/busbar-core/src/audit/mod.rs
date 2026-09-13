// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT MODULE — the durable, scope-keyed journal and the shared audit vocabulary.
//!
//! ## The chain primitive moved out, byte-for-byte
//!
//! The append-only hash chain — `Digest`, `frame_prelude`, `ChainedRecord`, `seal`, `Chain`,
//! `verify_chain`, `verify_window`, `ChainBreak` — used to live HERE. It now lives in
//! [`busbar_unit_audit::legacy::chain`], moved rather than rewritten: every byte the mechanism
//! produces is already on somebody's disk, so the framing, the field order, the sequence allocation,
//! the linkage and the walk travel unchanged. A digest that moved would make every deployed chain
//! fail to verify at its next boot — that is, report the whole of a deployment's history as TAMPERED
//! — so this is the one migration the code may never do silently, and it was done by identity.
//!
//! Owner's ruling, 2026-08-13: *"auditing is core. nothing auditing wise should be mcp a2a or llm
//! specific. thats how audits break."* busbar sells TAMPER-EVIDENCE: one append, one digest and one
//! verifier, so that "what happened" has ONE answer. A plane supplies the RECORD (which fields, in
//! which order, framed how — [`busbar_unit_audit::legacy::chain::ChainedRecord`]); it never supplies
//! the mechanism.
//!
//! ## What still lives here
//!
//! - [`journal`] — the generic scope-keyed durable position machine (the seq-authority state machine
//!   over the chain), naming no plane. The three shipped streams cross it through its NEUTRAL surface.
//! - [`vocab`] — the shared operator vocabulary (outcomes, reasons, dispositions), re-exported from
//!   the neutral substrate so every stream names one set of words.
//!
//! ## The claim, stated honestly
//!
//! TAMPER-EVIDENCE, not tamper-prevention. A chain detects an altered, reordered, inserted or removed
//! record AFTER the fact; it does not stop one, and a host compromised at the moment of writing can
//! rewrite a whole chain consistently and this will verify. Prevention means shipping the records
//! off-box to something the compromised host cannot rewrite.

pub mod journal;
pub mod vocab {
    pub use busbar_substrate::audit::vocab::*;
}

#[cfg(test)]
#[path = "tests/chain_tests.rs"]
mod chain_tests;

#[cfg(test)]
#[path = "tests/boot_verify_golden.rs"]
mod boot_verify_golden;
