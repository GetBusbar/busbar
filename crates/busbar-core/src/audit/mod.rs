// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPEND-ONLY HASH CHAIN — one mechanism, in core, for every stream of evidence busbar keeps.
//!
//! ## Why this is core and not a plane's
//!
//! Owner's ruling, 2026-08-13: *"auditing is core. nothing auditing wise should be mcp a2a or llm
//! specific. thats how audits break."* It is exact, and the reason is the product claim rather than
//! tidiness. busbar sells TAMPER-EVIDENCE: a chain detects an altered, reordered, inserted or
//! deleted record after the fact. THREE chain implementations mean three answers to "what happened",
//! and an auditor reads whichever one was wired last. A per-plane audit does not merely duplicate
//! code — it falsifies the property the code exists to provide.
//!
//! So there is ONE append ([`Chain::append`]/[`seal`]), ONE digest ([`digest`]) and ONE verifier
//! ([`verify_chain`]/[`verify_window`]), and they live here. A plane supplies the RECORD; it never
//! supplies the mechanism. [`crate::trust`] is the precedent this copies rather than a new idea: it
//! owns the trust lifecycle while a plane supplies only the artifact, and `a2a/pin.rs` says so in
//! its own header — *"A2A supplies an artifact; it does not supply a second state machine."*
//!
//! ## ONE MECHANISM IS NOT ONE STREAM, and conflating them would be a different defect
//!
//! Three chains run on this one mechanism and they stay SEPARATE:
//!
//! | stream | scope of a chain | rate |
//! |---|---|---|
//! | [`crate::admin::audit`] — admin MUTATIONS | one chain, process-wide | operator-rate |
//! | [`crate::calllog`] — MCP tool CALLS | one chain per PRINCIPAL | request-rate |
//! | [`crate::provenance`] — A2A task EVENTS | one chain per TASK | task-rate |
//!
//! `mcp/calllog.rs`'s own header records why the per-call event was moved OFF the admin ring: an
//! admin mutation is operator-rate and a tool call is REQUEST-rate, so sharing one bounded ring
//! means a busy afternoon evicts every admin record, silently. Unifying the MECHANISM must not
//! re-merge the STREAMS, and it does not: [`ChainedRecord::scope_of`] is what keeps them apart, and
//! the verifier REFUSES a record whose scope is not the chain's ([`ChainBreakKind::ForeignScope`]),
//! so one caller's evidence can never be made to depend on another caller's rows. store-mysql had a
//! real cross-principal read defect of exactly that shape (a case-insensitive collation let one key
//! id read another's chain), and the scope check is the engine-side half of not repeating it.
//!
//! ## WHAT A PLANE STILL OWNS: which fields the digest covers
//!
//! The three digests cover different fields, and that difference is legitimate — an admin mutation
//! has an `action` and a `resource`, a tool call has a `tool` and a pin generation, a task event has
//! a state. So [`ChainedRecord::digest_fields`] is the ONE thing a record type supplies about the
//! digest: which fields, in which order. Everything else — the sequence allocation, the `prev_hash`
//! linkage, the canonicalisation, the hash function and the verification walk — is here, once.
//!
//! ADDING A FOURTH STREAM COSTS A RECORD TYPE AND NOTHING ELSE. That is the acceptance test for this
//! seam, and `tests/chain_tests.rs` writes a throwaway fourth record type and chains and verifies it
//! with no new mechanism, so the claim is checked rather than asserted.
//!
//! ## The claim, stated honestly
//!
//! TAMPER-EVIDENCE, not tamper-prevention. A chain detects an altered, reordered, inserted or
//! removed record AFTER the fact; it does not stop one, and a host compromised at the moment of
//! writing can rewrite a whole chain consistently and this will verify. Prevention means shipping
//! the records off-box to something the compromised host cannot rewrite. Anything stronger said
//! about it is oversold.

//! ## WHERE THE MECHANISM ACTUALLY LIVES, since D33-R5
//!
//! [`busbar_unit_audit::legacy::chain`]. Everything above is still true — one append, one digest,
//! one verifier, a plane supplies the RECORD and never the mechanism — and the only thing that
//! changed is which crate the one copy sits in. Core held it because core was the only place there
//! was; the audit unit is the place there is now, it depends on nothing that could cycle back here,
//! and a mechanism that is re-implemented per caller is the defect this module was written to
//! prevent, so it may not be re-implemented per CRATE either.
//!
//! This module is now the SPELLING. `crate::audit::{Chain, Digest, seal, verify_chain, …}` resolve
//! to the unit's items, so every call site above reads as it always did, and the visibility each
//! item had here is the visibility it keeps: the mechanism stays `pub(crate)`, and [`ChainBreak`]
//! and [`ChainBreakKind`] stay `pub` because they were.
//!
//! The move is byte-exact by construction and by test. `tests/chain_tests.rs` still recomputes the
//! MCP per-call and admin-mutation digests the OLD way, in this crate, against the unit's mechanism;
//! `tests/boot_verify_golden.rs` still hands frozen pre-cleave persisted bytes to the real
//! boot-verify path and requires the recompute to reproduce the hash a past build sealed. Both had
//! to keep working across the move, and both did, unedited apart from where the names come from.

pub mod journal;
pub mod vocab {
    pub use busbar_substrate::audit::vocab::*;
}

/// The two operator-facing halves of a verification failure. `pub` here because they were `pub`
/// here: a caller outside core that already names `busbar_core::audit::ChainBreak` keeps naming it.
pub use busbar_unit_audit::legacy::chain::{ChainBreak, ChainBreakKind};

/// The mechanism. Deliberately `pub(crate)`, exactly as it was when the bodies were in this file —
/// widening core's public surface is not part of moving a body out of it.
pub(crate) use busbar_unit_audit::legacy::chain::{
    frame_prelude, seal, verify_chain, verify_window, Chain, ChainLabels, ChainedRecord, Digest,
    Framing,
};

/// The verification primitive. Production reaches it through [`verify_chain`]/[`verify_window`] and
/// [`seal`]; only the byte-identity tests below recompute a digest directly.
#[cfg(test)]
pub(crate) use busbar_unit_audit::legacy::chain::digest;

#[cfg(test)]
#[path = "tests/chain_tests.rs"]
mod chain_tests;

#[cfg(test)]
#[path = "tests/boot_verify_golden.rs"]
mod boot_verify_golden;
