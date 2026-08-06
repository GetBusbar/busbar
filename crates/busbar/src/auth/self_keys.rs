// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SELF-SERVE key SEAM (1.5.2 token-exchange).
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

use async_trait::async_trait;

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
/// ASYNC because the ONE production impl auto-provisions the personal budget group through the
/// async config-mutation choke point (`json::txn::config_transaction`) before it mints.
#[async_trait]
pub(crate) trait SelfServeKeys: Send + Sync {
    /// Issue the ONE key for `principal` (idempotent: a re-login returns the same key, only the
    /// token's `exp` refreshed). `ttl` is the token lifetime.
    async fn issue(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String>;
    /// ROTATE the key for `principal` (the "Refresh" action): the prior token stops verifying.
    async fn refresh(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String>;
}

/// AUTO-PROVISION the personal budget bucket a self-serve key charges through. Behind a trait so the
/// mint seam stays free of the config/cost machinery (and so tests can drive a fake): the ONE concrete
/// impl ([`HandleProvisioner`]) mirrors the admin auto-provision path exactly (`plan_mint_group` →
/// `persist_provisioned_group`), routed through the SAME `json::txn::config_transaction` choke point
/// the admin mint uses — so there is one lock, one fresh snapshot, one persist-then-swap for EVERY
/// config mutation in the tree (a self-mint provision and a concurrent admin `config/apply` serialize
/// against each other, no lost update).
///
/// THIS IS THE 1.5.2 TOKEN-EXCHANGE BUG FIX. Before it, a self-serve exchange minted a key bound to
/// `user:<sub>` but NEVER materialised that group in the cost model, so the very first request on the
/// minted key failed CLOSED with `429 group '<user:sub>' is not configured` (`MissingGroup`) —
/// contradicting the documented "budget auto-provisioned … created on first exchange". The mint now
/// provisions the `user:<sub>` LEAF under the resolved team (limits stamped from the team's
/// `child_default`, nearest-ancestor-wins) BEFORE issuing the token, so the key is usable immediately.
///
/// ASYNC because provisioning routes through the async `config_transaction`; the fakes in tests carry
/// no await but implement the same async signature via `#[async_trait]`.
#[async_trait]
pub(crate) trait SelfGroupProvisioner: Send + Sync {
    /// Ensure `leaf` exists as an enabled child of `parent`, limits copied from the nearest-ancestor
    /// `child_default` (inherit-only when none up the chain) — exactly the admin auto-provision shape.
    /// IDEMPOTENT: a no-op (never a reset) when `leaf` already exists, so N logins for one subject
    /// leave exactly one leaf with its usage intact. `Err(msg)` fails the mint closed (a key with no
    /// resolvable budget group is worse than no key).
    async fn ensure_leaf(&self, leaf: &str, parent: &str) -> Result<(), String>;
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

#[async_trait]
impl SelfServeKeys for DeterministicEd25519Keys {
    async fn issue(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String> {
        let now = crate::store::now();
        let exp = now.saturating_add(ttl.as_secs());
        // FIX: provision the personal budget bucket under the resolved team BEFORE minting, so the
        // issued key resolves a real group at admission instead of 429 MissingGroup. Idempotent.
        self.provisioner
            .ensure_leaf(&Self::self_group(principal), &self.team)
            .await?;
        // Offloaded: `issue_self` holds a std::sync::Mutex across synchronous store I/O, so
        // request-path callers must never invoke it directly on the reactor. See
        // `governance::mint_self_offloaded`.
        let (binding, token) = crate::governance::mint_self_offloaded(
            self.gov.clone(),
            crate::governance::SelfMintOp::Issue,
            principal.id.clone(),
            self.allowed_pools.clone(),
            exp,
            now,
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(IssuedKey {
            secret: token,
            key_id: binding.id,
            group: binding.group.unwrap_or_default(),
            exp,
        })
    }

    async fn refresh(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String> {
        let now = crate::store::now();
        let exp = now.saturating_add(ttl.as_secs());
        // Same provision-before-mint as `issue` (idempotent; the leaf already exists on a refresh).
        self.provisioner
            .ensure_leaf(&Self::self_group(principal), &self.team)
            .await?;
        // Offloaded: `refresh_self` holds the same std::sync::Mutex across synchronous store
        // I/O (write + delete). See `governance::mint_self_offloaded`.
        let (binding, token) = crate::governance::mint_self_offloaded(
            self.gov.clone(),
            crate::governance::SelfMintOp::Refresh,
            principal.id.clone(),
            self.allowed_pools.clone(),
            exp,
            now,
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(IssuedKey {
            secret: token,
            key_id: binding.id,
            group: binding.group.unwrap_or_default(),
            exp,
        })
    }
}

/// The production [`SelfGroupProvisioner`]: mirrors the admin `POST /keys?parent=` auto-provision
/// (`plan_mint_group` builds the leaf from the team's `child_default`; `persist_provisioned_group`
/// commits it PERSIST-then-SWAP, rebuilding the cost model so the new bucket is enforceable on the
/// next request and durable across restart) — but routed through the ONE config-mutation choke point
/// [`crate::admin::v1::json::config_transaction`], exactly as the admin mint is. That is the single
/// serialization point for EVERY config mutation, so this no longer needs (or has) its own lock: the
/// transaction's `CONFIG_MUTATION_LOCK` serializes a first-login provision against a concurrent admin
/// `config/apply`, closing the lost-update the previous ad-hoc `SELF_PROVISION_LOCK` could not.
pub(crate) struct HandleProvisioner {
    handle: Arc<crate::state::AppHandle>,
    actor: String,
}

impl HandleProvisioner {
    pub(crate) fn new(handle: Arc<crate::state::AppHandle>, actor: String) -> Self {
        Self { handle, actor }
    }
}

#[async_trait]
impl SelfGroupProvisioner for HandleProvisioner {
    async fn ensure_leaf(&self, leaf: &str, parent: &str) -> Result<(), String> {
        // Route the provision through the ONE config-mutation transaction: it takes the mutation
        // lock, hands the body a FRESH post-lock snapshot, and applies the plan as a single
        // persist-then-swap. No `commit_and_swap` by hand, no second lock — the same door the admin
        // mint (`create_key` auto-provision) walks through, so the two cannot lose a swap to each
        // other. `AdminError` is mapped to the mint's `String` failure at the boundary.
        let leaf = leaf.to_string();
        let parent = parent.to_string();
        let actor = self.actor.clone();
        crate::admin::v1::json::config_transaction(&self.handle, move |txn| {
            let current = txn.app();
            // IDEMPOTENT no-op: the leaf is already a live enforcement bucket (the steady-state
            // re-login path — no swap, no overlay churn, no usage reset).
            if current.cost.group_named(&leaf).is_some() {
                return Ok(txn.done(()));
            }
            // Same plan the admin mint runs: build the leaf under `parent` from the nearest-ancestor
            // `child_default`, validated at the door (cost rebuilt in the candidate snapshot).
            let Some(installed) =
                crate::admin::v1::json::plan_mint_group(current, &leaf, Some(&parent), &actor)?
            else {
                // `plan_mint_group` returns `None` only when the group already exists (a race with
                // the `group_named` check above lost) — nothing to commit.
                return Ok(txn.done(()));
            };
            // PERSIST-then-SWAP the new leaf, fail-closed — routed through `commit_and_swap` by the
            // transaction's sole apply site, never by hand here.
            let persist = crate::admin::v1::json::persist_provisioned_group(
                installed.clone(),
                leaf.clone(),
                actor.clone(),
            );
            Ok(txn.commit(installed, persist, ()))
        })
        .await
        .map_err(|e| e.message())
    }
}

/// Why an exchange was refused. Mapped to a status by the HTTP handler: `StaticKeyPresented`
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
/// auto-provisioned under — always present, a self key must charge through a group), and the C6
/// pool-union over EVERY granting binding, on success, or the typed refusal.
///
/// Both the group selection and the pool union mirror `synthesize_principal_key`'s (governance/mod.rs)
/// scan of ALL granting bindings — not just the one binding the group happened to come from: the group
/// is the first granting binding that carries one; the pools are the union of `allowed_pools` across
/// every granting binding, where an OMITTED `allowed_pools` on any of them widens the union to ALL
/// pools (`None`), and every one of them saying `allowed_pools: []` unions to the empty set. The one
/// deliberate divergence from `synthesize_principal_key`: that function returns NO key at all for an
/// empty-set union (an ad-hoc synthesized key that grants nothing is pointless), while this function
/// still returns `Ok` with `Some(vec![])` — a self-serve key is a real, persisted binding for an
/// admitted identity, and `GovState::issue_self`/`refresh_self` already encode `Some([])` as "mint the
/// key, but it grants no pool" (C6).
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
            // ALL of the principal's granting bindings in this module (mirrors
            // `synthesize_principal_key`'s `granting` scan) — not just the first role that happens
            // to have a binding. A principal can hold multiple roles; an earlier-listed role's
            // binding may be groupless while a later one carries the group that actually admits it.
            let granting: Vec<&crate::config::RoleBindingCfg> = principal
                .roles
                .iter()
                .filter_map(|r| table.get(r))
                .collect();
            if granting.is_empty() {
                return Err(ExchangeError::Unbound);
            }
            // parent = the FIRST granting binding that carries a group (scan ALL granting bindings,
            // not just the first-matched role) — a self key MUST charge through a group (no
            // unbounded self key), but that group may come from any one of the principal's roles.
            let team = granting
                .iter()
                .find_map(|b| b.group.clone())
                .ok_or(ExchangeError::Unbound)?;
            sanitize_self_sub(&principal.id)?;
            // POOLS: the C6 UNION across ALL granting bindings — IDENTICAL to
            // `synthesize_principal_key`'s pool-union loop (governance/mod.rs), not just the pools of
            // the single binding the group was taken from. An OMITTED `allowed_pools` on ANY granting
            // binding widens the union to ALL pools (`None`); otherwise the union is the de-duplicated
            // concatenation of every granting binding's explicit list. Unlike `synthesize_principal_key`
            // (which, for an ad-hoc synthesized key, returns no key at all when the union is the empty
            // set), a self-serve key is always minted for an admitted identity — an every-binding-`[]`
            // union yields `Some(vec![])`, the SAME "no pools" encoding `GovState::issue_self`/
            // `refresh_self` already special-case ("C6 intent carried intact: None = all pools;
            // Some([]) = none"), so the minted key exists but grants no data-plane pool.
            let mut pools: Vec<String> = Vec::new();
            let mut all_pools = false;
            for b in &granting {
                match b.allowed_pools.as_deref() {
                    None => all_pools = true,
                    Some(list) => {
                        for p in list {
                            if !pools.contains(p) {
                                pools.push(p.clone());
                            }
                        }
                    }
                }
            }
            let allowed_pools = if all_pools { None } else { Some(pools) };
            Ok((principal, team, allowed_pools))
        }
        // No identity established (all-Pass default, or an explicit Reject) → 401.
        ChainVerdict::Open | ChainVerdict::Denied => Err(ExchangeError::Unauthorized),
    }
}

/// Issue (or refresh) via the SEAM — depends ONLY on `&dyn SelfServeKeys`, so the endpoint is
/// key-scheme agnostic (a fake impl drives the same path in tests).
pub(crate) async fn issue_key(
    keys: &dyn SelfServeKeys,
    principal: &Principal,
    ttl: Duration,
    refresh: bool,
) -> Result<IssuedKey, ExchangeError> {
    let r = if refresh {
        keys.refresh(principal, ttl).await
    } else {
        keys.issue(principal, ttl).await
    };
    r.map_err(ExchangeError::MintFailed)
}

#[cfg(test)]
#[path = "tests/self_keys_tests.rs"]
mod self_keys_tests;
