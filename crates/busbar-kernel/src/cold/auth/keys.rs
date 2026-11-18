// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code for `auth::challenge`, `auth::exchange` and `auth::self_keys`: a refused request's
//! challenge head, and the rare self-serve key mint (a token exchange) that owns its names once.

use std::fmt::Write as _;

use crate::auth::challenge::Quoted;

/// The `WWW-Authenticate` challenge of a refused request (RFC 6750 §3), written once in place.
/// `description` and `scope` arrive already filtered for the challenge's error.
#[cold]
pub(crate) fn www_authenticate(
    code: Option<&str>,
    resource_metadata: &str,
    description: Option<&str>,
    scope: Option<&str>,
) -> String {
    let sized =
        resource_metadata.len() + description.map_or(0, str::len) + scope.map_or(0, str::len);
    let mut out = String::with_capacity(96 + sized);
    let _ = write!(
        out,
        "Bearer resource_metadata=\"{}\"",
        Quoted(resource_metadata)
    );
    if let Some(code) = code {
        let _ = write!(out, ", error=\"{code}\"");
    }
    if let Some(d) = description {
        let _ = write!(out, ", error_description=\"{}\"", Quoted(d));
    }
    if let Some(s) = scope {
        let _ = write!(out, ", scope=\"{}\"", Quoted(s));
    }
    out
}

/// A refused request's challenge head fields: the JSON content type and the challenge itself
/// (the bare `Bearer` when the challenge is not a valid header value).
#[cold]
pub(crate) fn challenge_fields(challenge: String) -> crate::plane_driver::HeadFields {
    let www_authenticate = if axum::http::HeaderValue::from_str(&challenge).is_ok() {
        challenge.into_bytes()
    } else {
        b"Bearer".to_vec()
    };
    vec![
        (b"content-type".to_vec(), b"application/json".to_vec()),
        (b"www-authenticate".to_vec(), www_authenticate),
    ]
}

/// The provider name a self-serve key is minted under, owned once per exchange.
#[cold]
pub(crate) fn self_key_provider(provider: &str) -> String {
    provider.to_owned()
}

/// The mint refusal when governance is disabled.
#[cold]
pub(crate) fn governance_disabled() -> String {
    "governance is disabled: cannot mint keys".to_owned()
}

/// The personal budget group a self-serve key charges through (`user:<sub>`).
#[cold]
pub(crate) fn self_group(principal_id: &str) -> String {
    format!(
        "{}{}",
        crate::governance::SELF_KEY_GROUP_PREFIX,
        principal_id
    )
}

/// What one self-serve mint owns: the minted key's allowed scopes, kept by the key record. The
/// subject and the provider are lent, not copied.
#[cold]
pub(crate) fn self_mint_scopes(
    allowed_scopes: Option<&[busbar_contract::records::ScopeRef]>,
) -> Option<Vec<busbar_contract::records::ScopeRef>> {
    allowed_scopes.map(<[busbar_contract::records::ScopeRef]>::to_vec)
}

/// A self-serve mint's store failure, as its `MintFailed` detail.
#[cold]
pub(crate) fn mint_store_failed(error: &dyn std::fmt::Display) -> String {
    error.to_string()
}

/// What a self-serve group provision owns across its config transaction: the leaf, its parent
/// and the acting principal.
#[cold]
pub(crate) fn provision_parts(leaf: &str, parent: &str, actor: &str) -> (String, String, String) {
    (leaf.to_owned(), parent.to_owned(), actor.to_owned())
}

/// The audit row of a token exchange refused because its verified principal is held (`auth:<module>`
/// names the instance that identified it). Spelled only on that refusal.
#[cold]
#[inline(never)]
pub(crate) fn exchange_principal_held(module: &str) {
    crate::audit::auditlog::emit_admin_hostless_now(
        "principal_held",
        &format!("auth:{module}"),
        busbar_contract::vocab::OUTCOME_REFUSED,
        crate::audit::auditlog::PLUGIN_REFUSAL_PRINCIPAL,
    );
}
