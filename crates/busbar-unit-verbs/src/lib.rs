// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! # busbar-unit-verbs — the kernel verbs, executed
//!
//! The admin plane is a CODEC ONLY: it decodes an HTTP request into a [`verb::KernelVerb`] and a
//! request body, and encodes whatever this crate returns back into an HTTP response. Every kernel
//! verb's SEMANTICS — what a mint actually does, what a rotate actually does, whether a call is
//! rate-limited, whether an `Idempotency-Key` retry replays instead of double-running, whether a
//! new 1.6.0 verb is admitted under the current dual-control posture — live here, behind the
//! [`governance::Governance`] and [`store::Store`] traits the integrator binds to the concrete
//! record store (`busbar-core`'s `GovState` and neighbours, in the target architecture).
//!
//! ## The closed table
//!
//! [`verb::KernelVerb`] is the closed set: 66 legacy operations mechanically derived from 1.5.5's
//! `openapi.json` at the tag (49 paths, 34 `read-only` / 32 `full`), the 17 new 1.6.0 verbs, and
//! the named non-admin surfaces (`/auth/token`, `/v1/models`, `/v1beta/models`, `/stats`,
//! `/healthz`, `/metrics`, `/metrics/hooks`). A test in `src/tests/table_matches_openapi.rs` parses
//! the committed `testing/shadow-oracle/fixtures/openapi-1.5.5.json` fixture and fails the build if
//! the legacy 66 and this table ever disagree, by even one operation or one required scope.
//!
//! ## What this crate depends on, and why nothing else
//!
//! `busbar-caps` only (a `serde_json` DEV-dependency exists solely to parse the openapi fixture in
//! the conformance test above; it is not part of the shipped crate). This crate holds
//! [`busbar_caps::AdminToken`] (lent by reference from the kernel — this crate never mints one; see
//! `busbar_caps::token` for why minting is confined to the kernel) and is the one place a
//! [`busbar_caps::SecretOnce`] is built for an administrative mint or rotate.
//!
//! ## What is ported IN FULL versus what is `// contract:`
//!
//! Ported in full, with the same assertions the 1.5.5 admin handler unit tests made: the
//! idempotency cache ([`idempotency`]; per-node, in-process, 600 s TTL, keyed `(actor, header)` for
//! a mint and `(actor, "rotate:{id}:{k}")` for a rotate, no body hash), the mutation rate limiter
//! ([`rate`]; fixed one-minute windows, `Config`/`Crud`/`PluginInspect` budgets, failed attempts
//! count too), the mint's parent-existence-only group plan ([`mint`]), and the posture rules for
//! the 17 new verbs ([`posture`]; refused under `operator: unset` except `set_operator_key` and
//! `export_keyset`; refused under `required` dual control without a matching `approve`).
//!
//! Everything else a legacy verb or a new verb actually DOES to the record store — 60 of the 66
//! legacy operations, and the domain effect of every new verb once posture admits it — is a
//! `// contract:` seam on [`governance::Governance`] or [`store::Store`]: this crate enforces the
//! SHAPE of the call (which verb, what scope it needs, which rate class, whether it replays), the
//! integrator supplies the effect. See those two modules' doc comments for the exact list of what
//! could not be ported and why (the concrete config/key/hook/plugin record types live in
//! `busbar-core`, which this crate does not, and must not, depend on).

pub mod governance;
pub mod idempotency;
pub mod mint;
pub mod posture;
pub mod rate;
pub mod refusal;
pub mod store;
pub mod verb;
pub mod verbs;

pub use governance::{Governance, GovernanceError, MintedKey, RotateOutcome};
pub use idempotency::ReplayEncoder;
pub use posture::{ApprovalState, DualControl, OperatorState, PostureCtx};
pub use rate::ConfigClassRule;
pub use refusal::{ReasonCode, Refusal, RefusalStep};
pub use store::{Store, StoreError};
pub use verb::{
    KernelVerb, VerbScope, IRREDUCIBLE_VERBS, LEDGER_VERBS, LEGACY_VERBS, NAMED_SURFACES, NEW_VERBS,
};
pub use verbs::{required_scope, MintOutcome, MintedKeyOutcome, NonceSource, Verbs};

#[cfg(test)]
#[path = "tests/table_matches_openapi.rs"]
mod table_matches_openapi;
