// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SELF-SERVE key SEAM (1.5.2 token-exchange, Step 4).
//!
//! `POST /auth/token` and the hosted browser login flow depend ONLY on the [`SelfServeKeys`] trait —
//! never on `TokenSigner`, the ed25519 envelope, the epoch, or any mint internal. The concrete
//! [`DeterministicEd25519Keys`] holds the entire mechanism ("Model B" — see
//! `GovState::issue_self`): a busbar-standard signed token whose SUBJECT id is derived
//! deterministically so the mint is an idempotent upsert of the one `user:<sub>` binding, and
//! Refresh bumps a per-principal epoch. Swapping the key scheme later is a new impl behind this
//! trait; the endpoint, the login flow, the docs and the tests are unchanged.
//!
//! Identity ALWAYS comes from the VERIFIED principal ([`ChainVerdict::Identified`]'s `principal.id`),
//! never from the request body — [`resolve_exchange`] takes the verdict, not any caller-supplied
//! identity, so there is no seam through which a caller could self-scope a key to someone else.

use std::sync::Arc;
use std::time::Duration;

use super::{ChainVerdict, Principal};
use crate::config::RoleBindings;
use crate::governance::GovState;

/// One issued self-serve key. The `secret` is the full busbar token (shown to the caller); `key_id`
/// is its stable subject id (`vk_...`), `group` the `user:<sub>` budget bucket, `exp` the Unix-secs
/// expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuedKey {
    pub(crate) secret: String,
    pub(crate) key_id: String,
    pub(crate) group: String,
    pub(crate) exp: u64,
}

/// The self-serve key scheme, isolated behind a trait so the exchange endpoint is scheme-agnostic.
pub(crate) trait SelfServeKeys {
    /// Issue the ONE key for `principal` (idempotent: a re-login returns the same key, only the
    /// token's `exp` refreshed). `ttl` is the token lifetime.
    fn issue(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String>;
    /// ROTATE the key for `principal` (the "Refresh" action): the prior token stops verifying.
    fn refresh(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String>;
}

/// AUTO-PROVISION the personal budget bucket a self-serve key charges through. Behind a trait so the
/// mint seam stays free of the config/cost machinery (and so tests can drive a fake): the ONE concrete
/// impl ([`HandleProvisioner`]) mirrors the admin auto-provision path exactly (`plan_mint_group` →
/// `persist_provisioned_group` → `commit_and_swap`).
///
/// THIS IS THE 1.5.2 TOKEN-EXCHANGE BUG FIX. Before it, a self-serve exchange minted a key bound to
/// `user:<sub>` but NEVER materialised that group in the cost model, so the very first request on the
/// minted key failed CLOSED with `429 group '<user:sub>' is not configured` (`MissingGroup`) —
/// contradicting the documented "budget auto-provisioned … created on first exchange". The mint now
/// provisions the `user:<sub>` LEAF under the resolved team (limits stamped from the team's
/// `child_default`, nearest-ancestor-wins) BEFORE issuing the token, so the key is usable immediately.
pub(crate) trait SelfGroupProvisioner: Send + Sync {
    /// Ensure `leaf` exists as an enabled child of `parent`, limits copied from the nearest-ancestor
    /// `child_default` (inherit-only when none up the chain) — exactly the admin auto-provision shape.
    /// IDEMPOTENT: a no-op (never a reset) when `leaf` already exists, so N logins for one subject
    /// leave exactly one leaf with its usage intact. `Err(msg)` fails the mint closed (a key with no
    /// resolvable budget group is worse than no key).
    fn ensure_leaf(&self, leaf: &str, parent: &str) -> Result<(), String>;
}

/// The concrete, GovState-backed scheme: deterministic ed25519 signed tokens ("Model B").
pub(crate) struct DeterministicEd25519Keys {
    gov: Arc<GovState>,
    /// The TEAM group the principal's role binds to (`role_bindings.<module>.<role>.group`) — the
    /// PARENT under which the per-user `user:<sub>` leaf is auto-provisioned. Resolved by
    /// [`resolve_exchange`] (guaranteed present: a self key must charge through a group).
    team: String,
    /// The pools this principal's bound role grants (C6: `None` = all, `Some([])` = none). Resolved
    /// from `role_bindings` by [`resolve_exchange`] and carried onto the minted binding.
    allowed_pools: Option<Vec<String>>,
    /// Provisions the `user:<sub>` leaf under `team` before the token is minted (the bug fix).
    provisioner: Arc<dyn SelfGroupProvisioner>,
}

impl DeterministicEd25519Keys {
    pub(crate) fn new(
        gov: Arc<GovState>,
        team: String,
        allowed_pools: Option<Vec<String>>,
        provisioner: Arc<dyn SelfGroupProvisioner>,
    ) -> Self {
        Self {
            gov,
            team,
            allowed_pools,
            provisioner,
        }
    }

    /// The `user:<sub>` leaf group this principal's key charges through.
    fn self_group(principal: &Principal) -> String {
        format!(
            "{}{}",
            crate::governance::SELF_KEY_GROUP_PREFIX,
            principal.id
        )
    }
}

impl SelfServeKeys for DeterministicEd25519Keys {
    fn issue(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String> {
        let now = crate::store::now();
        let exp = now.saturating_add(ttl.as_secs());
        // FIX: provision the personal budget bucket under the resolved team BEFORE minting, so the
        // issued key resolves a real group at admission instead of 429 MissingGroup. Idempotent.
        self.provisioner
            .ensure_leaf(&Self::self_group(principal), &self.team)?;
        let (binding, token) = self
            .gov
            .issue_self(&principal.id, self.allowed_pools.clone(), exp, now)
            .map_err(|e| e.to_string())?;
        Ok(IssuedKey {
            secret: token,
            key_id: binding.id,
            group: binding.group.unwrap_or_default(),
            exp,
        })
    }

    fn refresh(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String> {
        let now = crate::store::now();
        let exp = now.saturating_add(ttl.as_secs());
        // Same provision-before-mint as `issue` (idempotent; the leaf already exists on a refresh).
        self.provisioner
            .ensure_leaf(&Self::self_group(principal), &self.team)?;
        let (binding, token) = self
            .gov
            .refresh_self(&principal.id, self.allowed_pools.clone(), exp, now)
            .map_err(|e| e.to_string())?;
        Ok(IssuedKey {
            secret: token,
            key_id: binding.id,
            group: binding.group.unwrap_or_default(),
            exp,
        })
    }
}

/// Serializes self-serve leaf provisioning among themselves (the check→build→swap must not
/// interleave with another self-mint's). Process-global: one busbar owns one live `AppHandle`.
//
// NOTE (design wart, follow-up): this does NOT share the admin plane's async `CONFIG_MUTATION_LOCK`,
// so a concurrent admin `config/apply` racing a first-login provision is a theoretical lost-update on
// the `App` swap. In practice provisioning is a rare first-login-per-user event and the common
// re-login path is a lock-free `group_named` no-op. Unifying the two under one mutation choke point is
// tracked as follow-up.
static SELF_PROVISION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The production [`SelfGroupProvisioner`]: mirrors the admin `POST /keys?parent=` auto-provision
/// (`plan_mint_group` builds the leaf from the team's `child_default`; `persist_provisioned_group`
/// commits it PERSIST-then-SWAP through the live [`AppHandle`], rebuilding the cost model so the new
/// bucket is enforceable on the next request and durable across restart).
pub(crate) struct HandleProvisioner {
    handle: Arc<crate::state::AppHandle>,
    actor: String,
}

impl HandleProvisioner {
    pub(crate) fn new(handle: Arc<crate::state::AppHandle>, actor: String) -> Self {
        Self { handle, actor }
    }
}

impl SelfGroupProvisioner for HandleProvisioner {
    fn ensure_leaf(&self, leaf: &str, parent: &str) -> Result<(), String> {
        let _g = SELF_PROVISION_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let current = self.handle.load();
        // IDEMPOTENT no-op: the leaf is already a live enforcement bucket (the steady-state re-login
        // path — no swap, no overlay churn, no usage reset).
        if current.cost.group_named(leaf).is_some() {
            return Ok(());
        }
        // Same plan the admin mint runs: build the leaf under `parent` from the nearest-ancestor
        // `child_default`, validated at the door (cost rebuilt in the candidate snapshot).
        let planned =
            crate::admin::v1::json::plan_mint_group(&current, leaf, Some(parent), &self.actor)
                .map_err(|e| e.message())?;
        let Some(installed) = planned else {
            // `plan_mint_group` returns `None` only when the group already exists (a race with the
            // `group_named` check above lost) — nothing to commit.
            return Ok(());
        };
        let persist = crate::admin::v1::json::persist_provisioned_group(
            installed.clone(),
            leaf.to_string(),
            self.actor.clone(),
        );
        self.handle.commit_and_swap(installed, persist)
    }
}

/// Why an exchange was refused. Mapped to a status by the HTTP handler (Step 6): `StaticKeyPresented`
/// → 400, `Unauthorized` → 401, `Unbound`/`BadSubject` → 403, `MintFailed` → 500.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExchangeError {
    /// A static busbar key was presented (`resolved.is_some()`), not an IdP identity → 400.
    StaticKeyPresented,
    /// The chain did not identify anyone (Open/Denied) → vendor 401.
    Unauthorized,
    /// Identified, but no role of the principal is bound under the identifying module, or the bound
    /// role has no `group` to charge through → 403.
    Unbound,
    /// The principal id is not a safe self-serve subject (reserved/ambiguous) → 403.
    BadSubject,
    /// The mint itself failed (no signing key, store error) → 500.
    MintFailed(String),
}

/// Reject a principal id that cannot safely become a `user:<sub>` self-serve subject. A
/// module-namespaced subject (`oidc:<sub>`, `github:<login>`, `ldap:<dn>`, …) is LEGITIMATE and
/// verified — the auth chain established it — so an INTERNAL `:` is ALLOWED: the self group is ALWAYS
/// `user:` + the WHOLE sub, so an internal `:` cannot escape the `user:` namespace, and the derived
/// `vk_` id is `HMAC(user:<sub>#epoch)` so it cannot alias another subject. What IS refused (fail
/// closed): an empty sub, the `/` route separator, any control character, and a LEADING reserved
/// bucket/real-key prefix (`vk_`, `user:`, `group:`) — the shapes that could alias a reserved bucket
/// or a real key.
fn sanitize_self_sub(sub: &str) -> Result<(), ExchangeError> {
    let leading_reserved =
        sub.starts_with("vk_") || sub.starts_with("user:") || sub.starts_with("group:");
    if sub.is_empty()
        || sub.contains('/')
        || sub.chars().any(|c| c.is_control())
        || leading_reserved
    {
        tracing::warn!(
            sub = %sub,
            "token-exchange: refusing a principal id unsafe as a self-serve subject (empty, a '/' \
             route separator, a control char, or a leading reserved 'vk_'/'user:'/'group:' prefix)"
        );
        return Err(ExchangeError::BadSubject);
    }
    Ok(())
}

/// Decide whether a chain verdict may mint a self-serve key, and resolve the TEAM + pools to mint
/// under. The identity comes SOLELY from the verdict's `principal` — never from any request body.
/// Returns the verified principal, the bound TEAM group (the PARENT the per-user `user:<sub>` leaf is
/// auto-provisioned under — always present, a self key must charge through a group), and its bound
/// pools on success, or the typed refusal.
pub(crate) fn resolve_exchange<'a>(
    verdict: &'a ChainVerdict,
    role_bindings: &RoleBindings,
) -> Result<(&'a Principal, String, Option<Vec<String>>), ExchangeError> {
    match verdict {
        ChainVerdict::Identified {
            module,
            principal,
            resolved,
        } => {
            // A STATIC busbar key was presented (the engine resolved a VirtualKey). Token-exchange
            // is for IdP identities minting THEIR OWN key — not for re-wrapping an existing one.
            if resolved.is_some() {
                return Err(ExchangeError::StaticKeyPresented);
            }
            // role_bindings are nested BY MODULE; a role only grants under its identifying module.
            let table = role_bindings.get(module).ok_or(ExchangeError::Unbound)?;
            let binding = principal
                .roles
                .iter()
                .find_map(|r| table.get(r))
                .ok_or(ExchangeError::Unbound)?;
            // parent = binding.group; a self key MUST charge through a group (no unbounded self key).
            let team = binding.group.clone().ok_or(ExchangeError::Unbound)?;
            sanitize_self_sub(&principal.id)?;
            Ok((principal, team, binding.allowed_pools.clone()))
        }
        // No identity established (all-Pass default, or an explicit Reject) → 401.
        ChainVerdict::Open | ChainVerdict::Denied => Err(ExchangeError::Unauthorized),
    }
}

/// Issue (or refresh) via the SEAM — depends ONLY on `&dyn SelfServeKeys`, so the endpoint is
/// key-scheme agnostic (a fake impl drives the same path in tests).
pub(crate) fn issue_key(
    keys: &dyn SelfServeKeys,
    principal: &Principal,
    ttl: Duration,
    refresh: bool,
) -> Result<IssuedKey, ExchangeError> {
    let r = if refresh {
        keys.refresh(principal, ttl)
    } else {
        keys.issue(principal, ttl)
    };
    r.map_err(ExchangeError::MintFailed)
}

#[cfg(test)]
#[path = "tests/self_keys_tests.rs"]
mod self_keys_tests;
