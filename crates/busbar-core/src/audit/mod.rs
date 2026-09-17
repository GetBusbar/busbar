// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPEND-ONLY HASH CHAIN — one mechanism, for every stream of evidence busbar keeps.
//!
//! ## Why this is audit-owned, re-exported here
//!
//! Owner's ruling, 2026-08-13 (paraphrased): auditing is core; nothing about it should be specific
//! to any one plugin. That's how audits break. It is exact, and the reason is the product claim
//! rather than tidiness. busbar sells TAMPER-EVIDENCE: a chain detects an altered, reordered,
//! inserted or deleted record after the fact. Several independent chain implementations mean
//! several answers to "what happened", and an auditor reads whichever one was wired last. A
//! per-plugin audit does not merely duplicate code — it falsifies the property the code exists to
//! provide.
//!
//! So there is ONE append ([`Chain::append`]/[`seal`]), ONE digest ([`digest`]) and ONE verifier
//! ([`verify_chain`]/[`verify_window`]). By the owner's 2026-09-08 ruling (`busbar-unit-audit::
//! journal`) that ONE mechanism now lives in the crate whose whole job is auditing —
//! [`busbar_unit_audit::legacy`] — and this module re-exports it UNCHANGED so every in-core call
//! site keeps naming `crate::audit::…`, and so the relocated [`journal`] is generic over the SAME
//! trait a plane's record implements. A plugin supplies the RECORD; it never supplies the mechanism.
//! [`crate::trust`] is the precedent this copies rather than a new idea: it owns the trust lifecycle
//! while a plugin supplies only the artifact, and a downstream plugin integration's own header states
//! the same rule for its own domain: a plugin supplies an artifact; it does not supply a second
//! state machine.
//!
//! ## ONE MECHANISM IS NOT ONE STREAM, and conflating them would be a different defect
//!
//! Several chains can run on this one mechanism and they stay SEPARATE:
//!
//! | stream | scope of a chain | rate |
//! |---|---|---|
//! | [`crate::audit_ring`] — admin MUTATIONS | one chain, process-wide | operator-rate |
//! | a per-caller request log kept by a downstream plugin | one chain per PRINCIPAL | request-rate |
//! | a per-task event log kept by a downstream plugin | one chain per TASK | task-rate |
//!
//! One such downstream stream's own header records why its per-call event was moved OFF the admin
//! ring: an admin mutation is operator-rate and a per-call event is REQUEST-rate, so sharing one
//! bounded ring means a busy afternoon evicts every admin record, silently. Unifying the MECHANISM
//! must not re-merge the STREAMS, and it does not: [`ChainedRecord::scope_of`] is what keeps them
//! apart, and the verifier REFUSES a record whose scope is not the chain's
//! ([`ChainBreakKind::ForeignScope`]), so one caller's evidence can never be made to depend on
//! another caller's rows. store-mysql had a real cross-principal read defect of exactly that shape
//! (a case-insensitive collation let one key id read another's chain), and the
//! scope check is the engine-side half of not repeating it.
//!
//! ## WHAT A PLUGIN STILL OWNS: which fields the digest covers
//!
//! Different streams cover different fields, and that difference is legitimate — an admin mutation
//! has an `action` and a `resource`, while a plugin-defined event may have entirely different
//! fields of its own. So [`ChainedRecord::digest_fields`] is the ONE thing a record type supplies
//! about the digest: which fields, in which order. Everything else — the sequence allocation, the
//! `prev_hash` linkage, the canonicalisation, the hash function and the verification walk — is
//! there, once.
//!
//! ## The claim, stated honestly
//!
//! TAMPER-EVIDENCE, not tamper-prevention. A chain detects an altered, reordered, inserted or
//! removed record AFTER the fact; it does not stop one, and a host compromised at the moment of
//! writing can rewrite a whole chain consistently and this will verify. Prevention means shipping
//! the records off-box to something the compromised host cannot rewrite. Anything stronger said
//! about it is oversold.

/// The generic scope-keyed durable journal, re-exported at its historical `crate::audit::journal::…`
/// path from its new home in the audit unit ([`busbar_unit_audit::journal`]). MOVED, not rewritten:
/// every persisted byte it produces is unchanged (owner ruling, 2026-09-08).
pub mod journal {
    pub use busbar_unit_audit::journal::*;
}

pub mod vocab {
    pub use busbar_substrate::audit::vocab::*;
}

// ── THE ONE MECHANISM, RE-EXPORTED FROM THE AUDIT UNIT ──────────────────────────────────────────
//
// Moved to `busbar-unit-audit` (the crate whose whole job is auditing), byte for byte, and
// re-exported here at the same visibility every in-core call site already relied on, so nothing
// about the framing, the field order, the digest or the walk changed — a moved byte would report
// every deployed chain's history as tampered at its next boot. Load-bearing: because these ARE the
// unit's types (not a copy), `crate::audit::ChainedRecord` and the relocated `journal` agree, so a
// plane's `ChainedRecord` impl satisfies the journal that is now generic over the unit's trait.
//
// The mechanism internals stay `pub(crate)` (their historical visibility — the lib/bin seam never
// exposed them); only the two verification-result types were ever `pub`, and they stay `pub`.
pub(crate) use busbar_unit_audit::legacy::{
    frame_prelude, seal, verify_chain, verify_window, Chain, ChainLabels, ChainedRecord, Digest,
    Framing,
};
pub use busbar_unit_audit::legacy::{ChainBreak, ChainBreakKind};
// The free recompute-a-record's-digest primitive is named only by in-crate tests
// (`crate::audit::digest`); re-exported at its historical path, unused in the non-test lib build.
#[allow(unused_imports)]
pub(crate) use busbar_unit_audit::legacy::digest;

#[cfg(test)]
#[path = "tests/chain_tests.rs"]
mod chain_tests;

#[cfg(test)]
#[path = "tests/boot_verify_golden.rs"]
mod boot_verify_golden;
