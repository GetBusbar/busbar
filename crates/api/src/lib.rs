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
mod secret;
mod store;
pub mod usage_migration;

// THE PLUGIN CONTRACTS LEFT THIS CRATE (DECISIONS #83/#84; the per-kind traits are the contract's,
// #35(a)). `auth`, `hooks`, `secret` and `operation` now live in `busbar_contract` under the same
// module names, moved module-path-only and byte-identical; these lines keep every `busbar_api::…`
// spelling resolving until the fold retires the crate. Two names were de-collided on the move (#35)
// and are aliased back here: `AuthVerdict` → `AuthOutcome`, `SecretModuleError` → `SecretError`.
pub use auth::{constant_time_eq, sha256_hex, UpstreamCreds};
pub use busbar_contract::auth::{
    AuthModule, AuthPrincipal, AuthVerdict as AuthOutcome, CallerToken, IdentityRefusal, Principal,
};
pub use busbar_contract::auth::{
    AuthPlugin, BeginLogin, CompleteLogin, FieldKind, LoginField, LoginForm, LoginHop,
    LoginHttpResponse, LoginKind, LoginModule, LoginOutcome,
};
pub use busbar_contract::hooks::{
    BudgetBucketState, CallerIdentity, Candidate, HookStatus, PolicyError, PolicyResult,
    PromptProjection, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest,
    TransformOutcome,
};
pub use busbar_contract::operation;
// `Redacted` and the signal catalog LEFT THIS CRATE (DECISIONS #84) and are re-exported, not
// defined, here. Both are SHAPES in the #83(d) sense — a redacting/zeroizing secret wrapper
// whose `Debug` every implementation must agree prints nothing, and a wire/config key catalog
// every implementation must spell identically — so they belong in the ONE contract crate
// (#38). These lines keep `busbar_api::Redacted`, `busbar_api::Signal`, `busbar_api::SignalBag`
// and `busbar_api::SignalValue` resolving for every caller that already spells them that way.
pub use busbar_contract::redacted::Redacted;
pub use busbar_contract::secret::{
    SecretErrorKind, SecretModule, SecretModuleError as SecretError, SecretResult,
};
pub use secret::{resolve_builtin, resolve_builtin_string, SecretResolve};
// The config secret-reference type, re-exported from the contract (the former `busbar-secret-ref`
// crate merged there, DECISIONS #83) so a plane crate names `busbar_api::SecretRef` unchanged.
pub use busbar_contract::signal::{Signal, SignalBag, SignalValue};
pub use busbar_contract::SecretRef;
pub use store::{
    register_scope_kind, AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow,
    ModelTokens, ModelTokensDelta, PlaneDisposition, PlaneRecord, PlaneRequestCtx, PlaneSelector,
    ScopeRef, SecretForm, Store, StoreError, StoreResult, UsageDelta, UsageLedger, VirtualKey,
    RESERVED_UNITS, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
