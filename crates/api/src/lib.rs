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
//!   the read-only projections it is invoked with — owned by `busbar-contract` now and re-exported
//!   here while this crate drains.
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
mod secret;
pub mod usage_migration;

pub use auth::{
    constant_time_eq, sha256_hex, AuthModule, AuthOutcome, AuthPrincipal, CallerToken,
    IdentityRefusal, Principal, UpstreamCreds,
};
pub use auth::{
    AuthPlugin, BeginLogin, CompleteLogin, FieldKind, LoginField, LoginForm, LoginHop,
    LoginHttpResponse, LoginKind, LoginModule, LoginOutcome,
};
// THE HOOKS-KIND FACE IS THE CONTRACT'S (`busbar-contract::hooks` / `::signal`). This crate is
// being deleted (Track 4); until the last reader of these paths is repointed it re-exports the
// face verbatim so nothing compiles against two definitions of one trait. The drain line is the
// reader: every `busbar_api::RoutingPolicy` spelling becomes `busbar_contract::RoutingPolicy`, and
// this block goes with the crate.
pub use busbar_contract::{
    ArgumentProjection, BudgetBucketState, CallerIdentity, Candidate, ClassRate, HookStatus,
    MeterClassId, PolicyError, PolicyResult, RewriteReply, RoutingContext, RoutingDecision,
    RoutingPolicy, RoutingRequest, TransformOutcome,
};
// THE RESIDUE IS THE CONTRACT'S TOO: the `Operation` axis (`operation`), the secret carrier
// (`Redacted`) and the signal catalog belong to no kind and moved to busbar-contract. Re-exported
// here while this crate drains; the drain line is the reader: `busbar_api::operation` becomes
// `busbar_contract::operation`, `busbar_api::Redacted` becomes `busbar_contract::redacted::Redacted`,
// and these lines go with the crate.
pub use busbar_contract::operation;
pub use busbar_contract::redacted::Redacted;
pub use secret::{
    resolve_builtin, resolve_builtin_string, SecretError, SecretErrorKind, SecretModule,
    SecretResolve, SecretResult,
};
// The config secret-reference type, re-exported from its own leaf crate so a plane crate names
// `busbar_api::SecretRef` without a separate path dep.
// The reserved module names a secret reference may carry travel with it: the substrate's
// resolver reads them through this crate rather than through a direct edge to the leaf.
pub use busbar_secret_grammar::{
    SecretRef, SECRET_MODULE_ENV, SECRET_MODULE_FILE, SECRET_MODULE_NONE,
};
// The signal catalog is the CONTRACT's now (it moved with the hooks-kind face); re-exported here
// while busbar-api drains, so every reader keeps its spelling and resolves to one definition.
pub use busbar_contract::{Signal, SignalBag, SignalValue};
// THE STORE-KIND FACE IS THE CONTRACT'S (`busbar_contract::store`): the records and the replay
// face the store plugins and the loader are written against moved there verbatim. Re-exported
// here while this crate drains; the drain line is the reader: every `busbar_api::<name>` below
// becomes `busbar_contract::store::<name>`, and this block goes with the crate.
pub use busbar_contract::store::{
    register_scope_kind, AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow,
    ModelTokens, ModelTokensDelta, PlaneDisposition, PlaneRecord, PlaneRequestCtx, PlaneSelector,
    ScopeRef, SecretForm, Store, StoreError, StoreResult, UsageDelta, UsageLedger, VirtualKey,
    RESERVED_UNITS, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
