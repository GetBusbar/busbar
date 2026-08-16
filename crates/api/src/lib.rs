// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar plugin CONTRACTS — the crate every plugin builds against, and nothing more.
//!
//! The engine (`busbar`) consumes plugins; plugins implement engine contracts. Both therefore
//! depend on this small, dependency-light crate, which holds exactly the shared surface:
//!
//! - **auth** — the [`AuthModule`] trait and its verdict types ([`AuthOutcome`], [`Principal`]),
//!   plus the constant-time credential primitives every module compares with.
//! - **hooks** — the [`RoutingPolicy`] trait (decide/transform/notify + configure/describe) and
//!   the read-only projections it is invoked with.
//! - **store** — the [`Store`] trait a `db` plugin implements, plus the durable-store records
//!   ([`VirtualKey`], [`UsageLedger`], [`CredentialMeta`], [`CredentialSecret`], …) it reads and
//!   writes.
//! - **secret** - the [`SecretModule`] trait a `kind: secret` plugin implements (a config secret
//!   reference's `settings` map in, the secret bytes out; fail-closed).
//! - **plane** - the [`plane::PlaneDecl`] a `kind: plane` plugin declares (config section, routes,
//!   scope/audit vocabulary) and the [`plane::PlaneHandler`] that serves it. A plane DECLARES and
//!   the core MOUNTS AND EXECUTES — the [`LoginHop`] shape, applied to the serving surface.
//!
//! Everything here is a CONTRACT, not machinery: no I/O, no engine state, no transport. A
//! third-party plugin crate that depends only on `busbar-api` is architecturally identical to a
//! built-in one.

mod auth;
pub mod breaker;
pub mod durable;
mod hooks;
pub mod ir;
pub mod plane;
pub mod protocol;
mod redacted;
mod secret;
mod signal;
mod store;

pub use auth::{constant_time_eq, sha256_hex, AuthModule, AuthOutcome, Principal};
pub use auth::{
    AuthPlugin, BeginLogin, CompleteLogin, FieldKind, LoginField, LoginForm, LoginHop,
    LoginHttpResponse, LoginKind, LoginModule, LoginOutcome,
};
pub use hooks::{
    BudgetBucketState, CallerIdentity, Candidate, HookStatus, PolicyError, PolicyResult,
    PromptProjection, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest,
    TransformOutcome,
};
pub use redacted::Redacted;
pub use secret::{SecretError, SecretErrorKind, SecretModule, SecretResult};
pub use signal::{Signal, SignalBag, SignalValue};
pub use store::{
    AuditRecord, CredentialMeta, CredentialSecret, McpCallRecord, McpDemotionRow, MeteringDelta,
    MeteringRow, ModelTokens, ModelTokensDelta, ScopeRef, SecretForm, Store, StoreError,
    StoreResult, TaskEventRow, TaskRow, TierTokens, TierTokensDelta, UsageDelta, UsageLedger,
    VirtualKey,
};

#[cfg(test)]
#[path = "tests/marshal_cost_tests.rs"]
mod marshal_cost_tests;
