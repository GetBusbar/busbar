// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::{ChainVerdict, Principal};
use crate::config::RoleBindings;
use crate::diagnostics::{diag_debug, SELF_SUBJECT_UNSAFE};
use crate::governance::GovState;

/// One issued self-serve key. The `secret` is the full busbar token (shown to the caller once); it is
/// held as [`Secret`](busbar_contract::redacted::Secret) so the struct's derived `Debug` cannot leak a LIVE
/// bearer token into a log/`tracing`/panic line — the value escapes only through the explicit
/// `.expose(&crate::seal::lend())` audit points (the once-shown mint response). `key_id` is its stable subject id
/// (`vk_...`) and IS the safe-to-log identity; `group` the `user:<sub>` budget bucket, `exp` the
/// Unix-secs expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuedKey {
    pub(crate) secret: busbar_contract::redacted::Secret<String>,
    pub(crate) key_id: String,
    pub(crate) group: String,
    pub(crate) exp: u64,
}

/// The self-serve key scheme, isolated behind a trait so the exchange endpoint is scheme-agnostic.
/// ASYNC because the ONE production impl auto-provisions the personal budget group through the
/// async config-mutation choke point (`crate::config::transaction::config_transaction`) before it
/// mints. A refusal comes back as its typed [`ExchangeError`] (`Unbound`), a failure as `MintFailed`.
#[async_trait]
pub(crate) trait SelfServeKeys: Send + Sync {
    /// Issue the ONE key for `principal` (idempotent: a re-login returns the same key, only the
    /// token's `exp` refreshed). `ttl` is the token lifetime.
    async fn issue(&self, principal: &Principal, ttl: Duration)
        -> Result<IssuedKey, ExchangeError>;
    /// ROTATE the key for `principal` (the "Refresh" action): the prior token stops verifying.
    async fn refresh(
        &self,
        principal: &Principal,
        ttl: Duration,
    ) -> Result<IssuedKey, ExchangeError>;
}

/// AUTO-PROVISION the personal budget bucket a self-serve key charges through. Behind a trait so the
/// mint seam stays free of the config/cost machinery (and so tests can drive a fake): the ONE concrete
/// impl ([`HandleProvisioner`]) mirrors the admin auto-provision path exactly (`plan_mint_group` →
/// `persist_provisioned_group`), routed through the SAME `config::transaction::config_transaction`
/// choke point
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
    /// IDEMPOTENT: a no-op (never a reset) when `leaf` already exists under `parent`, so N logins
    /// for one subject leave exactly one leaf with its usage intact. A different parent is refused;
    /// a mint cannot re-home an existing leaf. `Err(msg)` fails the mint closed.
    async fn ensure_leaf(&self, leaf: &str, parent: &str) -> Result<(), String>;
}

pub(crate) struct DeterministicEd25519Keys {
    gov: Arc<GovState>,

    provider: String,

    team: String,

    allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,

    provisioner: Arc<dyn SelfGroupProvisioner>,
}

impl DeterministicEd25519Keys {
    pub(crate) fn new(
        gov: Arc<GovState>,
        provider: String,
        team: String,
        allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
        provisioner: Arc<dyn SelfGroupProvisioner>,
    ) -> Self {
        Self {
            gov,
            provider,
            team,
            allowed_scopes,
            provisioner,
        }
    }

    fn self_group(principal: &Principal) -> String {
        format!(
            "{}{}",
            crate::governance::SELF_KEY_GROUP_PREFIX,
            principal.id
        )
    }

    async fn mint(
        &self,
        principal: &Principal,
        ttl: Duration,
        op: crate::governance::SelfMintOp,
    ) -> Result<IssuedKey, ExchangeError> {
        let now = busbar_kernel::store::now();
        let exp = now.saturating_add(ttl.as_secs());
        self.provisioner
            .ensure_leaf(&Self::self_group(principal), &self.team)
            .await
            .map_err(ExchangeError::MintFailed)?;

        mint_provisioned_self_key(
            self.gov.clone(),
            op,
            principal,
            &self.provider,
            self.allowed_scopes.clone(),
            exp,
            now,
        )
        .await
    }
}

// The continuation after the real provisioner has committed or reused the subject's leaf.
// The caller records now/exp before provisioning and passes those exact values here.
async fn mint_provisioned_self_key(
    gov: Arc<GovState>,
    op: crate::governance::SelfMintOp,
    principal: &Principal,
    provider: &str,
    allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
    exp: u64,
    now: u64,
) -> Result<IssuedKey, ExchangeError> {
    let (binding, token) = crate::governance::mint_self_offloaded(
        gov,
        op,
        principal.id.clone(),
        provider.to_string(),
        allowed_scopes,
        exp,
        now,
    )
    .await
    .map_err(|e| match e {
        crate::governance::SelfMintError::Refused(_) => ExchangeError::Unbound,
        crate::governance::SelfMintError::Store(e) => ExchangeError::MintFailed(e.to_string()),
    })?;
    Ok(IssuedKey {
        secret: busbar_contract::redacted::Secret::new(token),
        key_id: binding.id,
        group: binding.group.unwrap_or_default(),
        exp,
    })
}

#[async_trait]
impl SelfServeKeys for DeterministicEd25519Keys {
    async fn issue(
        &self,
        principal: &Principal,
        ttl: Duration,
    ) -> Result<IssuedKey, ExchangeError> {
        self.mint(principal, ttl, crate::governance::SelfMintOp::Issue)
            .await
    }

    async fn refresh(
        &self,
        principal: &Principal,
        ttl: Duration,
    ) -> Result<IssuedKey, ExchangeError> {
        self.mint(principal, ttl, crate::governance::SelfMintOp::Refresh)
            .await
    }
}

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
        let leaf = leaf.to_string();
        let parent = parent.to_string();
        let actor = self.actor.clone();
        crate::config::transaction::config_transaction(&self.handle, move |txn| {
            let current = txn.app();

            let Some(installed) = crate::governance::group_provision::plan_mint_group(
                current,
                &leaf,
                Some(&parent),
                &actor,
            )?
            else {
                return Ok(txn.done(()));
            };

            let persist = crate::governance::group_provision::persist_provisioned_group(
                installed.clone(),
                leaf.clone(),
                actor.clone(),
            );
            Ok(txn.commit(installed, persist, ()))
        })
        .await
        .map_err(|e: crate::config::transaction::TxnError| e.message())
    }
}

/// Why an exchange was refused. Mapped to a status by the HTTP handler: `StaticKeyPresented`
/// → 400, `Unauthorized` → 401, `SelfMintDisabled`/`Unbound`/`BadSubject`/`OverCeiling` → 403,
/// `MintFailed` → 500.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExchangeError {
    /// A static busbar key was presented (`resolved.is_some()`), not an IdP identity → 400.
    StaticKeyPresented,
    /// The chain did not identify anyone (Open/Denied) → vendor 401.
    Unauthorized,
    /// Self-serve minting is disabled by policy (`auth.policy.self_mint: false`) → 403. Checked only
    /// AFTER an identity is established, so an anonymous caller still reads as `Unauthorized` (401)
    /// and the disabled-mint policy is not disclosed to the unauthenticated.
    SelfMintDisabled,
    /// Identified, but no role of the principal is bound under the identifying module, or the bound
    /// role has no `group` to charge through, or (only with the unsigned
    /// [`crate::governance::SELF_MINT_HOLDS_ADMIN_AND_PROVIDER_STATE`] on) the subject's self-serve
    /// binding is disabled or was minted by another identity provider → 403.
    Unbound,
    /// The principal id is not a safe self-serve subject (reserved/ambiguous) → 403.
    BadSubject,
    /// The key this identity would mint is over the deployment's mint ceiling (`auth.policy`: the
    /// block `max_ttl`/`binding_modes` and the per-role `mint_ceilings`) → 403. The detail is the
    /// policy's own message, naming the ceiling that bit.
    OverCeiling(String),
    /// The mint itself failed (no signing key, store error) → 500.
    MintFailed(String),
}

fn sanitize_self_sub(sub: &str) -> Result<(), ExchangeError> {
    let leading_reserved =
        sub.starts_with("vk_") || sub.starts_with("user:") || sub.starts_with("group:");
    if sub.is_empty()
        || sub.contains('/')
        || sub.chars().any(|c| c.is_control())
        || leading_reserved
    {
        diag_debug!(
            SELF_SUBJECT_UNSAFE,
            sub = %sub,
            "token-exchange: refusing a principal id unsafe as a self-serve subject (empty, a '/' \
             route separator, a control char, or a leading reserved 'vk_'/'user:'/'group:' prefix)"
        );
        return Err(ExchangeError::BadSubject);
    }
    Ok(())
}

pub(crate) struct SelfMint<'a> {
    pub principal: &'a Principal,

    pub team: String,

    pub granted_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,

    pub ttl: Duration,
}

pub(crate) fn admit_self_mint<'a>(
    verdict: &'a ChainVerdict,
    role_bindings: &RoleBindings,
    policy: &crate::governance::mint_policy::MintPolicy,
    default_ttl_secs: u64,
) -> Result<SelfMint<'a>, ExchangeError> {
    let (principal, team, scopes) = resolve_exchange(verdict, role_bindings, policy.self_mint)?;
    let (pools, other_kinds) = crate::governance::mint_policy::requested_grant(scopes.as_deref());
    let ttl_secs = policy
        .check_mint(&crate::governance::mint_policy::MintRequest {
            roles: &principal.roles,
            requested_pools: pools.as_deref(),
            grants_other_kinds: other_kinds,
            requested_ttl_secs: default_ttl_secs,
            explicit_ttl: false,
            requested_mode: Some(crate::governance::SELF_KEY_BINDING_MODE),
        })
        .map_err(ExchangeError::OverCeiling)?;
    Ok(SelfMint {
        principal,
        team,
        granted_scopes: scopes,
        ttl: Duration::from_secs(ttl_secs),
    })
}

pub(crate) fn resolve_exchange<'a>(
    verdict: &'a ChainVerdict,
    role_bindings: &RoleBindings,
    self_mint: Option<bool>,
) -> Result<
    (
        &'a Principal,
        String,
        Option<Vec<busbar_contract::records::ScopeRef>>,
    ),
    ExchangeError,
> {
    match verdict {
        ChainVerdict::Identified {
            module,
            principal,
            resolved,
        } => {
            if self_mint == Some(false) {
                return Err(ExchangeError::SelfMintDisabled);
            }

            if resolved.is_some() {
                return Err(ExchangeError::StaticKeyPresented);
            }

            let table = role_bindings.get(module).ok_or(ExchangeError::Unbound)?;

            let granting = crate::governance::granting_bindings(principal, table);
            if granting.is_empty() {
                return Err(ExchangeError::Unbound);
            }

            let team = granting
                .iter()
                .find_map(|b| b.group.clone())
                .ok_or(ExchangeError::Unbound)?;
            sanitize_self_sub(&principal.id)?;

            let allowed_scopes = crate::governance::grant_union(&granting);
            Ok((principal, team, allowed_scopes))
        }

        ChainVerdict::Open | ChainVerdict::Denied => Err(ExchangeError::Unauthorized),
    }
}

pub(crate) async fn issue_key(
    keys: &dyn SelfServeKeys,
    principal: &Principal,
    ttl: Duration,
    refresh: bool,
) -> Result<IssuedKey, ExchangeError> {
    if refresh {
        keys.refresh(principal, ttl).await
    } else {
        keys.issue(principal, ttl).await
    }
}

#[cfg(test)]
#[path = "tests/self_keys_tests.rs"]
mod self_keys_tests;
