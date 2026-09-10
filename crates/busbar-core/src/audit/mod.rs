// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPEND-ONLY HASH CHAIN LIVES IN `busbar_unit_audit::legacy` — this module keeps only the
//! scope-keyed durable [`journal`] built on top of it.
//!
//! ## Where the mechanism went, and why there is no copy of it here
//!
//! Owner's ruling, 2026-08-13: *"auditing is core. nothing auditing wise should be mcp a2a or llm
//! specific. thats how audits break."* The ruling is about there being ONE mechanism, not about
//! which crate holds it. busbar sells TAMPER-EVIDENCE: a chain detects an altered, reordered,
//! inserted or deleted record after the fact. THREE chain implementations mean three answers to
//! "what happened", and an auditor reads whichever one was wired last.
//!
//! So there is ONE append (`Chain::append`/`seal`), ONE canonicaliser (`Digest`) and ONE verifier
//! (`verify_chain`/`verify_window`), and they are the audit unit's — moved rather than rewritten, so not one persisted byte changed. A
//! plane supplies the RECORD; it never supplies the mechanism. Every stream in this crate reads the
//! unit's face directly: there is deliberately no re-export here, because a spelling in core is how
//! a second mechanism grows back.
//!
//! ## ONE MECHANISM IS NOT ONE STREAM, and conflating them would be a different defect
//!
//! Two chains run on that one mechanism and they stay SEPARATE:
//!
//! | stream | scope of a chain | rate |
//! |---|---|---|
//! | [`crate::admin::audit`] — admin MUTATIONS | one chain, process-wide | operator-rate |
//! | [`crate::calllog`] — MCP tool CALLS | one chain per PRINCIPAL | request-rate |
//!
//! `calllog.rs`'s own header records why the per-call event was moved OFF the admin ring: an admin
//! mutation is operator-rate and a tool call is REQUEST-rate, so sharing one bounded ring means a
//! busy afternoon evicts every admin record, silently. Unifying the MECHANISM must not re-merge the
//! STREAMS, and it does not: `ChainedRecord::scope_of` is what keeps
//! them apart, and the verifier REFUSES a record whose scope is not the chain's
//! (`ChainBreakKind::ForeignScope`), so one caller's evidence can never
//! be made to depend on another caller's rows.
//!
//! ## WHAT A PLANE STILL OWNS: which fields the digest covers
//!
//! The digests cover different fields, and that difference is legitimate — an admin mutation
//! has an `action` and a `resource`, a tool call has a `tool` and a pin generation, a task event has
//! a state. So `ChainedRecord::digest_fields` is the ONE thing a record type supplies about the
//! digest: which fields, in which order. Everything else — the sequence allocation, the `prev_hash`
//! linkage, the canonicalisation, the hash function and the verification walk — is the unit's, once.
//!
//! ADDING A FOURTH STREAM COSTS A RECORD TYPE AND NOTHING ELSE. `tests/chain_tests.rs` writes a
//! throwaway fourth record type against the unit's trait and chains and verifies it with no new
//! mechanism, so the claim is checked rather than asserted; `tests/boot_verify_golden.rs` holds this
//! crate's three real streams against frozen persisted bytes, which is what proves the mechanism
//! moved without moving a digest.
//!
//! ## The claim, stated honestly
//!
//! TAMPER-EVIDENCE, not tamper-prevention. A chain detects an altered, reordered, inserted or
//! removed record AFTER the fact; it does not stop one, and a host compromised at the moment of
//! writing can rewrite a whole chain consistently and this will verify. Prevention means shipping
//! the records off-box to something the compromised host cannot rewrite. Anything stronger said
//! about it is oversold.

pub mod journal;

/// The audit VOCABULARY — the outcome and reason words the three streams share. A re-export and
/// nothing else, and the ONE place in this crate that names the module the words come from: the
/// fourteen call sites spell `crate::audit::vocab`, so they cost no further reach.
pub mod vocab {
    pub use busbar_substrate::audit::vocab::*;
}

#[cfg(test)]
#[path = "tests/chain_tests.rs"]
mod chain_tests;

#[cfg(test)]
#[path = "tests/boot_verify_golden.rs"]
mod boot_verify_golden;
