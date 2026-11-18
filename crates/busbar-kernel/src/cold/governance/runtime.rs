// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::runtime` cold code (see `crate::cold::governance`).

use busbar_contract::crypto;

/// `at_rest`: a credential seal refused (the CSPRNG or the cipher failed).
#[cold]
pub(crate) fn at_rest_seal_refusal(e: crypto::Error) -> String {
    match e {
        crypto::Error::Rng(e) => format!("CSPRNG unavailable: {e}"),
        _ => "the credential could not be sealed".to_owned(),
    }
}

/// `at_rest`: the sealed envelope, the stored row written once at mint or re-wrap.
#[cold]
pub(crate) fn at_rest_envelope(prefix: &str, kid: &str, nonce: &[u8], sealed: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{prefix}{kid}:{}:{}", b64.encode(nonce), b64.encode(sealed))
}

/// `at_rest`: a refused kid, remembered once (at most the cap) and audited once.
#[cold]
pub(crate) fn at_rest_refused_kid(seen: &mut std::collections::BTreeSet<String>, kid: &str) {
    seen.insert(kid.to_owned());
}

/// `at_rest`: the audit resource naming a refused kid, at most the cap times per process.
#[cold]
pub(crate) fn at_rest_kid_resource(kid: &str) -> String {
    format!("kid:{kid}")
}

/// `unit_checkpoint_store`: a failed checkpoint operation, rendered once on the error path.
#[cold]
pub(crate) fn unit_checkpoint_store_error(
    e: &dyn std::fmt::Debug,
) -> busbar_contract::records::RecordStoreError {
    busbar_contract::records::RecordStoreError::from(format!("unit checkpoint: {e:?}"))
}

/// `identity_runtime`: a credential mint refused because the CSPRNG failed.
#[cold]
pub(crate) fn identity_runtime_csprng_refusal(
    e: &dyn std::fmt::Display,
) -> busbar_contract::records::RecordStoreError {
    busbar_contract::records::RecordStoreError::from(format!("CSPRNG unavailable: {e}"))
}

/// `mint_policy`: an explicit mint lifetime over the policy ceiling, refused.
#[cold]
pub(crate) fn mint_policy_ttl_refusal(requested_ttl_secs: u64, max: u64) -> String {
    format!(
        "requested key lifetime ({requested_ttl_secs}s) exceeds the policy ceiling \
         auth.policy.max_ttl ({max}s); request a shorter expires_in/expires_at"
    )
}

/// `mint_policy`: a mint of ALL pools under a pool-capped role ceiling, refused.
#[cold]
pub(crate) fn mint_policy_all_pools_refusal(allowed: &dyn std::fmt::Display) -> String {
    format!(
        "the mint requests ALL pools but the caller's role ceiling \
         (auth.policy.mint_ceilings) allows only [{allowed}]; name an explicit subset"
    )
}

/// `mint_policy`: a mint naming a pool outside the role ceiling, refused.
#[cold]
pub(crate) fn mint_policy_pool_refusal(pool: &str, allowed: &dyn std::fmt::Display) -> String {
    format!(
        "pool '{pool}' is outside the caller's role mint ceiling \
         (auth.policy.mint_ceilings allows [{allowed}])"
    )
}

/// `mint_policy`: a mint granting non-pool scopes under a pool-capped role ceiling, refused.
#[cold]
pub(crate) fn mint_policy_other_kinds_refusal(allowed: &dyn std::fmt::Display) -> String {
    format!(
        "the mint grants scopes of a kind other than pools, but the caller's role \
         ceiling (auth.policy.mint_ceilings) allows only the pools [{allowed}]"
    )
}

/// `mint_policy`: a mint binding mode the policy does not permit, refused.
#[cold]
pub(crate) fn mint_policy_mode_refusal(mode: &str, allowed: &dyn std::fmt::Display) -> String {
    format!("binding mode '{mode}' is not permitted by policy (allowed: [{allowed}])")
}

/// `group_provision`: a refused group change, its message rendered once.
#[cold]
pub(crate) fn group_provision_refusal(
    kind: fn(String) -> crate::config::transaction::TxnError,
    args: std::fmt::Arguments<'_>,
) -> crate::config::transaction::TxnError {
    kind(std::fmt::format(args))
}

/// `group_provision`: the audit resource naming a group whose provision was refused.
#[cold]
pub(crate) fn group_provision_resource(group: &str) -> String {
    format!("group:{group}")
}

/// `group_provision`: an unconfirmed group persist, its refusal rendered once.
#[cold]
pub(crate) fn group_provision_persist_refusal(error: &dyn std::fmt::Display) -> String {
    format!(
        "group persistence to the Store overlay was not confirmed: {error}; the running group \
         tree is unaffected"
    )
}

/// `self_serve`: the audit resource of a self-serve mint refused because the key is on hold.
#[cold]
pub(crate) fn self_serve_held_resource(
    key_id: Option<&str>,
    user_sub: &str,
    reason: &str,
) -> String {
    match key_id {
        Some(id) => format!("key:{id}#{reason}"),
        None => format!("subject:{user_sub}#{reason}"),
    }
}

/// `native_runtime`: a failed observation read, rendered once on the error path.
#[cold]
pub(crate) fn native_runtime_store_error(
    error: &dyn std::fmt::Display,
) -> busbar_contract::records::RecordStoreError {
    busbar_contract::records::RecordStoreError::from(error.to_string())
}
