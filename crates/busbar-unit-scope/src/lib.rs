// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-scope — the APPROVE step
//!
//! The kernel loop's third step asks one question: does the principal hold enough scope for what
//! this operation needs? The APPROVE step looks up the required scope from `(claim, op_class)` in
//! Policy, the plane hands back resource locators only (never a decision), and a hook's veto is a
//! separate, closed code where the first veto at any seat wins. This crate is the "does the
//! principal hold enough scope" half of that: a small, pure data model with no I/O, no wire format
//! and no store, so it can be proven correct on its own and reused by every transport that needs an
//! authorization answer (today: the admin API).
//!
//! ## What is in here
//!
//! - [`Scope`] — the two-rung authorization chain (`ReadOnly` at the bottom, `Full` at the top),
//!   ported byte-for-byte from 1.5.5's admin API.
//! - [`Grants`] — the set a principal actually holds, once every role binding it matches has been
//!   unioned together and any ceiling has been applied.
//! - [`admin_required_scope`] — the admin-API scope matrix: derived from HTTP method and path alone
//!   (never the request body, so a crafted request cannot escalate), matching 1.5.5's
//!   `admin_required_scope(method, path)` operation-for-operation.
//! - [`ADMIN_SCOPE_TABLE`] — the 66 operations that matrix was mechanically extracted from at the
//!   1.5.5 tag (`v1.5.5`, `crates/busbar/src/admin/v1/json/openapi.json`), kept here as DATA so the
//!   rule above can be proven against every one of them instead of a hand-picked sample.
//! - [`KERNEL_GRANTED_DATA_LISTENER_ROUTES`] and [`is_kernel_granted`] — the scopes every principal holds without
//!   a `Policy` entry at all: the handshake scope every transport needs before it has authenticated
//!   anyone, and the data-listener operational routes that answer even when nothing else can.
//! - [`approve`] — the step itself: does a principal's [`Grants`] satisfy the [`Scope`] an
//!   operation requires.
//!
//! ## What is deliberately absent
//!
//! The full APPROVE step also resolves `(claim, op_class)` against `Policy` to find the required
//! scope in the first place, evaluates hook facts, and picks resource locators — all of that reaches
//! into the plane host, the policy store and the hook seat machinery, none of which this crate
//! depends on. What is here is the part that is pure data plus a pure function: the admin-API scope
//! table (a concrete, already-migrated instance of "required scope from (claim, op_class)") and the
//! two-rung authorization chain every caller of that lookup is checked against. `// contract:` marks
//! - [`PolicyView`] and [`required_scope`] — the `(claim, op_class)` lookup a 1.6.0-native plane's
//!   `Policy` entries are read through. The contract crate now carries a claim's name, so the pair
//!   the design makes the lookup key can finally be spelled; without the claim half, a native plane
//!   had no way to be scoped at all.
//!
//! The hook-veto seat is still absent: it reaches into the hook seat machinery, which this crate
//! does not depend on. A veto composes with the check here the way the design says — this runs
//! first, and a veto after it wins regardless of what it returned.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use busbar_contract::{ClaimKey, OpClassId};

/// The built-in authorization scopes — a strict two-rung chain: `ReadOnly` at the bottom, `Full` at
/// the top. Authorization is checked on the PRINCIPAL per endpoint and is NEVER derived from the
/// request body, so a crafted request cannot escalate.
///
/// 1.5.2 collapsed the former four-variant diamond (delegated `HooksRegister`/`Mint` sibling scopes)
/// down to these two: every read is `ReadOnly`, every mutation is `Full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every read (`GET`/`HEAD`) plus the stateless dry-run `POST`s that lint without mutating
    /// anything.
    ReadOnly,
    /// Everything: every mutation.
    Full,
}

impl Scope {
    /// The stable wire token for this scope.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::ReadOnly => "read-only",
            Scope::Full => "full",
        }
    }

    /// Parse a config-side scope token (`role_bindings.<m>.<role>.admin_scope`,
    /// `max_admin_scope:`). `None` = unknown token: a caller treats that as no grant (fail closed).
    /// The retired `hooks-register`/`mint` tokens parse to `None` too.
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "read-only" => Some(Scope::ReadOnly),
            "full" => Some(Scope::Full),
            _ => None,
        }
    }

    /// Whether a principal holding `self` may call an endpoint requiring `needed`. A strict chain:
    /// `ReadOnly` is satisfied by anything (every grant can read); `Full` is satisfied only by
    /// `Full`.
    pub fn allows(self, needed: Scope) -> bool {
        match needed {
            Scope::ReadOnly => true,
            Scope::Full => self == Scope::Full,
        }
    }

    /// Every scope, for the closure operations below. Adding a variant means adding it here too.
    const ALL: [Scope; 2] = [Scope::ReadOnly, Scope::Full];

    /// This scope's bit in a [`Grants`] bitset.
    fn bit(self) -> u8 {
        1u8 << Scope::ALL
            .iter()
            .position(|s| *s == self)
            .expect("Scope::ALL enumerates every variant")
    }

    /// Does holding `self` confer everything holding `other` confers? Derived from `allows`, never
    /// a second hand-written table.
    fn dominates(self, other: Scope) -> bool {
        Scope::ALL
            .iter()
            .all(|n| !other.allows(*n) || self.allows(*n))
    }

    /// The greatest scope conferring no more than either operand — the ceiling operator (the meet
    /// of the two-rung chain): the lower of the two, i.e. `ReadOnly` unless both are `Full`.
    pub fn meet(self, other: Scope) -> Scope {
        if self.dominates(other) {
            other
        } else if other.dominates(self) {
            self
        } else {
            Scope::ReadOnly
        }
    }
}

/// The effective authority of a principal: a SET of scopes. Roles union into it ([`Grants::with`]);
/// a module ceiling meets each member ([`Grants::capped_by`]). A bitset over `Scope::ALL` — `Copy`,
/// no allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Grants(u8);

impl Grants {
    /// The single-scope grant.
    pub fn of(s: Scope) -> Self {
        Grants(s.bit())
    }

    /// Union — add `s` to the held grants. Folding a principal's role bindings with `with` keeps
    /// every scope a role grants, so two roles together keep both instead of an ordinal `max`
    /// collapsing to one and losing the other.
    pub fn with(self, s: Scope) -> Self {
        Grants(self.0 | s.bit())
    }

    /// Pointwise `meet` against a ceiling. Each held scope is capped independently, so a principal
    /// capped below one of two incomparable grants doesn't lose the other.
    pub fn capped_by(self, cap: Scope) -> Self {
        Scope::ALL
            .iter()
            .filter(|s| self.contains(**s))
            .fold(Grants::default(), |acc, s| acc.with(s.meet(cap)))
    }

    /// The authorization check: does ANY held scope satisfy `needed`?
    pub fn allows(self, needed: Scope) -> bool {
        Scope::ALL
            .iter()
            .any(|s| self.contains(*s) && s.allows(needed))
    }

    /// Exact membership — for a caller that must name one specific scope, not "does this authorize
    /// X".
    pub fn contains(self, s: Scope) -> bool {
        self.0 & s.bit() != 0
    }
}

/// The kernel-granted scope every principal holds before Policy has ever been consulted — including
/// `Principal::Anonymous`. It is never a `Policy` key: a transport needs it to run its handshake
/// before anyone has been authenticated at all, so making it a grant a config could omit would leave
/// the very first frame of every connection with no scope to check against.
pub const TRANSPORT_HANDSHAKE: &str = "transport:handshake";

/// The data-listener operational routes that carry a kernel-granted scope and 1.5.5's own auth rule
/// rather than an admin credential: they answer even when the admin credential store, or the whole
/// governance posture, is unavailable, because they are what an operator or a load balancer polls to
/// find out whether anything else can answer at all.
pub const KERNEL_GRANTED_DATA_LISTENER_ROUTES: &[&str] =
    &["/healthz", "/stats", "/metrics", "/metrics/hooks"];

/// Whether `path` is one of the kernel-granted data-listener routes — present on both listeners,
/// bypassing the ordinary admin-scope check entirely. Matched on the exact path, the same
/// way the routes are mounted; a path with a differing prefix or suffix is not one of these.
pub fn is_kernel_granted(path: &str) -> bool {
    KERNEL_GRANTED_DATA_LISTENER_ROUTES.contains(&path)
}

/// The frozen Admin API v1 path prefix every operation in [`ADMIN_SCOPE_TABLE`] is mounted under.
pub const ADMIN_PREFIX: &str = "/api/v1/admin";

/// `POST /config/validate` and `POST /plugins/inspect` — stateless dry-runs (reads in POST
/// clothing: the body is the config to lint / tarball to preview) that stay `read-only` although
/// every other mutation-shaped method needs `full`.
const READ_ONLY_POST_PATHS: &[&str] = &["/config/validate", "/plugins/inspect"];

/// The authorization matrix: the scope an admin endpoint requires, derived from METHOD + PATH —
/// never from the body. A strict two-rung split: every read (`GET`/`HEAD`) plus the two stateless
/// dry-run `POST`s is `read-only`; every mutation needs `full`. Unknown methods fail closed to
/// `full`.
///
/// Ported verbatim from 1.5.5's `busbar_core::admin::v1::contract::required_scope` (behaviourally
/// identical; the only change is that `method` is a plain string here instead of `axum::http::Method`,
/// so this crate carries no HTTP-framework dependency at all).
pub fn admin_required_scope(method: &str, path: &str) -> Scope {
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        return Scope::ReadOnly;
    }
    let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
    if method.eq_ignore_ascii_case("POST") && READ_ONLY_POST_PATHS.contains(&rel) {
        return Scope::ReadOnly;
    }
    Scope::Full
}

/// One admin operation in the 1.5.5 scope table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminOperation {
    /// The HTTP method.
    pub method: &'static str,
    /// The absolute path, `ADMIN_PREFIX`-rooted.
    pub path: &'static str,
    /// The scope 1.5.5 requires for this operation.
    pub scope: Scope,
}

/// The 1.5.5 admin scope table, as data: 66 operations over 49 paths (34 `read-only`, 32 `full`),
/// derived mechanically from 1.5.5's `openapi.json` at the `v1.5.5` tag
/// (`crates/busbar/src/admin/v1/json/openapi.json`'s `x-busbar-required-scope` annotations) —
/// pinned by git object hash. `POST /config/validate` and `POST /plugins/inspect` are read-only.
/// This is the "1.5.5 scope table as data" [`admin_required_scope`] is proven against, row for row, in
/// the table test.
///
/// `// contract:` the richer `(claim, op_class) -> Scope` lookup a 1.6.0-native plane's `Policy`
/// entries would add lands here once the contract crate carries `ClaimKey`/`OpClass`; every entry
/// below is the migrated, already-closed instance of that lookup for the admin plane.
pub static ADMIN_SCOPE_TABLE: &[AdminOperation] = &[
    op("DELETE", "/api/v1/admin/export/{name}", Scope::Full),
    op("DELETE", "/api/v1/admin/groups/{name}", Scope::Full),
    op("DELETE", "/api/v1/admin/hooks/{name}", Scope::Full),
    op(
        "DELETE",
        "/api/v1/admin/identity-providers/{name}",
        Scope::Full,
    ),
    op("DELETE", "/api/v1/admin/keys/{id}", Scope::Full),
    op("DELETE", "/api/v1/admin/overlay/{section}", Scope::Full),
    op("DELETE", "/api/v1/admin/plugins/{file}", Scope::Full),
    op("GET", "/api/v1/admin/admin-auth", Scope::ReadOnly),
    op("GET", "/api/v1/admin/audit", Scope::ReadOnly),
    op("GET", "/api/v1/admin/auth", Scope::ReadOnly),
    op("GET", "/api/v1/admin/config", Scope::ReadOnly),
    op("GET", "/api/v1/admin/config/diff", Scope::ReadOnly),
    op("GET", "/api/v1/admin/config/settings", Scope::ReadOnly),
    op("GET", "/api/v1/admin/config/versions", Scope::ReadOnly),
    op("GET", "/api/v1/admin/config/versions/{v}", Scope::ReadOnly),
    op("GET", "/api/v1/admin/export", Scope::ReadOnly),
    op("GET", "/api/v1/admin/export/{name}", Scope::ReadOnly),
    op("GET", "/api/v1/admin/groups", Scope::ReadOnly),
    op("GET", "/api/v1/admin/groups/{name}", Scope::ReadOnly),
    op("GET", "/api/v1/admin/groups/{name}/usage", Scope::ReadOnly),
    op("GET", "/api/v1/admin/hooks", Scope::ReadOnly),
    op("GET", "/api/v1/admin/hooks/{name}", Scope::ReadOnly),
    op("GET", "/api/v1/admin/hooks/{name}/health", Scope::ReadOnly),
    op("GET", "/api/v1/admin/hooks/{name}/schema", Scope::ReadOnly),
    op("GET", "/api/v1/admin/hooks/{name}/status", Scope::ReadOnly),
    op("GET", "/api/v1/admin/identity-providers", Scope::ReadOnly),
    op(
        "GET",
        "/api/v1/admin/identity-providers/{name}",
        Scope::ReadOnly,
    ),
    op("GET", "/api/v1/admin/info", Scope::ReadOnly),
    op("GET", "/api/v1/admin/keys", Scope::ReadOnly),
    op("GET", "/api/v1/admin/keys/{id}", Scope::ReadOnly),
    op("GET", "/api/v1/admin/keys/{id}/usage", Scope::ReadOnly),
    op("GET", "/api/v1/admin/models", Scope::ReadOnly),
    op("GET", "/api/v1/admin/openapi.json", Scope::ReadOnly),
    op("GET", "/api/v1/admin/plugins", Scope::ReadOnly),
    op(
        "GET",
        "/api/v1/admin/plugins/{file}/schema",
        Scope::ReadOnly,
    ),
    op("GET", "/api/v1/admin/pools", Scope::ReadOnly),
    op("GET", "/api/v1/admin/pools/{name}", Scope::ReadOnly),
    op("GET", "/api/v1/admin/providers", Scope::ReadOnly),
    op("GET", "/api/v1/admin/usage", Scope::ReadOnly),
    op("PATCH", "/api/v1/admin/export/{name}/settings", Scope::Full),
    op("PATCH", "/api/v1/admin/groups/{name}", Scope::Full),
    op("PATCH", "/api/v1/admin/hooks/{name}/settings", Scope::Full),
    op(
        "PATCH",
        "/api/v1/admin/identity-providers/{name}/settings",
        Scope::Full,
    ),
    op("PATCH", "/api/v1/admin/keys/{id}", Scope::Full),
    op("POST", "/api/v1/admin/auth/cache/flush", Scope::Full),
    op("POST", "/api/v1/admin/config/apply", Scope::Full),
    op("POST", "/api/v1/admin/config/reload", Scope::Full),
    op("POST", "/api/v1/admin/config/rollback", Scope::Full),
    op("POST", "/api/v1/admin/config/validate", Scope::ReadOnly),
    op("POST", "/api/v1/admin/groups", Scope::Full),
    op("POST", "/api/v1/admin/hooks", Scope::Full),
    op("POST", "/api/v1/admin/keys", Scope::Full),
    op("POST", "/api/v1/admin/keys/{id}/revoke", Scope::Full),
    op("POST", "/api/v1/admin/keys/{id}/rotate", Scope::Full),
    op("POST", "/api/v1/admin/plugins", Scope::Full),
    op("POST", "/api/v1/admin/plugins/inspect", Scope::ReadOnly),
    op("POST", "/api/v1/admin/plugins/reload", Scope::Full),
    op("POST", "/api/v1/admin/plugins/rollback", Scope::Full),
    op("POST", "/api/v1/admin/restart", Scope::Full),
    op("POST", "/api/v1/admin/signing-key/rotate", Scope::Full),
    op("PUT", "/api/v1/admin/admin-auth", Scope::Full),
    op("PUT", "/api/v1/admin/config/settings", Scope::Full),
    op("PUT", "/api/v1/admin/export/{name}", Scope::Full),
    op("PUT", "/api/v1/admin/groups/{name}", Scope::Full),
    op("PUT", "/api/v1/admin/hooks/{name}", Scope::Full),
    op(
        "PUT",
        "/api/v1/admin/identity-providers/{name}",
        Scope::Full,
    ),
];

/// `const fn` builder for [`ADMIN_SCOPE_TABLE`] rows, so the table above is data, not a macro.
const fn op(method: &'static str, path: &'static str, scope: Scope) -> AdminOperation {
    AdminOperation {
        method,
        path,
        scope,
    }
}

/// Why the APPROVE step refused a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The principal's held [`Grants`] do not satisfy the required [`Scope`].
    InsufficientScope {
        /// The scope that would have sufficed.
        needed: Scope,
    },
}

/// Where the required scope for a claim's operation class is read from.
///
/// A trait rather than a table, because the entries live in the sealed `Policy` the composition
/// root holds and this crate owns no policy store. The admin matrix above is one already-closed
/// instance of the same lookup, written out as data because it is byte-pinned parity surface.
pub trait PolicyView {
    /// The scope this claim's operation class requires, where the policy says anything about it.
    fn required_scope(&self, claim: ClaimKey, op: OpClassId) -> Option<Scope>;
}

/// The APPROVE step's lookup: the scope a claim's operation class requires.
///
/// A kernel-granted operation needs no policy entry at all and answers before the policy is asked —
/// that is what lets a transport hand shake before it has authenticated anyone, and what keeps the
/// data listener's operational routes answering when nothing else can.
///
/// Everything else is a policy question, and a pair the policy says nothing about has NO required
/// scope. That is a refusal rather than a pass: an operation nobody wrote a policy entry for has
/// not been authorized, and a plane that could be scoped by silence could be scoped by omission.
#[must_use]
pub fn required_scope(claim: ClaimKey, op: OpClassId, policy: &dyn PolicyView) -> Option<Scope> {
    policy.required_scope(claim, op)
}

/// The APPROVE step: does `held` satisfy `needed`? Kernel-granted operations
/// ([`TRANSPORT_HANDSHAKE`], [`is_kernel_granted`]) are checked by the caller before reaching here —
/// this function is the ordinary `Policy`-scope comparison for everything else. Resource locators
/// and hook facts (the rest of APPROVE) are the plane's and the hook seats' concern; `// contract:`
/// once those live in the contract crate, they compose with this the same way `plane.approve()`
/// composes with the scope lookup in the kernel loop: this check runs first, and a hook veto after
/// it wins regardless of what this returns.
pub fn approve(held: Grants, needed: Scope) -> Result<(), Refused> {
    if held.allows(needed) {
        Ok(())
    } else {
        Err(Refused::InsufficientScope { needed })
    }
}

#[cfg(test)]
mod tests;
