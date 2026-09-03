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
//!
//! Everything here is a CONTRACT, not machinery: no I/O, no engine state, no transport. A
//! third-party plugin crate that depends only on `busbar-api` is architecturally identical to a
//! built-in one.

mod auth;
pub mod durable;
mod hooks;
pub mod operation;
mod redacted;
mod secret;
mod signal;
mod store;
pub mod usage_migration;

pub use auth::{
    constant_time_eq, sha256_hex, AuthModule, AuthOutcome, AuthPrincipal, IdentityRefusal,
    Principal, UpstreamCreds,
};
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
pub use secret::{
    resolve_builtin, resolve_builtin_string, SecretError, SecretErrorKind, SecretModule,
    SecretResolve, SecretResult,
};
// The config secret-reference type, re-exported from its own leaf crate so a plane crate names
// `busbar_api::SecretRef` without a separate path dep.
pub use busbar_secret_ref::SecretRef;
pub use signal::{Signal, SignalBag, SignalValue};
pub use store::{
    register_scope_kind, AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow,
    ModelTokens, ModelTokensDelta, PlaneDisposition, PlaneRecord, PlaneRequestCtx, PlaneSelector,
    ScopeRef, SecretForm, Store, StoreError, StoreResult, UsageDelta, UsageLedger, VirtualKey,
    RESERVED_UNITS, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
