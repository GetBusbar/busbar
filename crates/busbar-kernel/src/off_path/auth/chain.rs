// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth chain's off-path code: the data and admin chains, the operator provider and the
//! credential readers built once per configuration load, the admin service's views of them, and
//! the admin plane's verify-request construction and its keys position and scope caps (the node's
//! configuration plane, not the data path). The request path reads only what this builds.

use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;

use crate::auth::{
    carried_named, instances, AdminAuthChain, AdminDoor, AuthMiddleware, ChainVerdict, KeysAdmin,
    Operator, Principal, VerbAllowList,
};
use crate::config::AuthCfg;
use crate::diagnostics::{diag_warn, AUTH_CHAIN_OPEN_RELAY};
use busbar_contract::auth_calls::AuthCalls;

impl AdminAuthChain {
    pub fn build(
        cfg: &AuthCfg,
        registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        Self::build_on(cfg, registry.as_ref(), secret_resolver)
    }

    /// The admin chain: `keys`, an unset operator row and a module a native auth image answers
    /// open nothing here; any other module is refused once its settings resolve (no `kind: auth`
    /// plugin answers it).
    pub(crate) fn build_on(
        cfg: &AuthCfg,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        let op = crate::config::operator_provider();
        let is_op = |m: &str| crate::config::names_operator(m);
        for entry in &cfg.admin_auth {
            let backed = Operator::backed(op, &entry.name, Some(entry.module.as_str()), &is_op);
            match entry.module.as_str() {
                // An operator-backed entry with no settings is unset: nothing opens.
                _ if backed && entry.settings.is_empty() => {}
                // The built-in `keys` position opens no plugin: the admin chain judges it itself.
                crate::config::KEYS_MODULE => {}
                // A native (MIN-3) auth image's admin chain is the root's native one (min3_admin_auth), built over its
                // opened instance; the door axis does not answer it, so it opens nothing here.
                other if crate::preflight::native_auth_answers(other) => {}
                other => {
                    let name = entry.name.as_str();
                    instances::provider_settings(
                        cfg,
                        name,
                        other,
                        &entry.settings,
                        registry,
                        secret_resolver,
                        |e| format!("identity-providers.{name} settings: {e}"),
                    )?;
                    return Err(format!(
                        "auth.admin_auth provider '{name}' (module '{other}') could not be loaded \
                         as a `kind: auth` plugin: no `kind: auth` plugin answers to '{other}'"
                    ));
                }
            }
        }
        let defs = cfg
            .methods
            .iter()
            .map(|(n, m)| (n.as_str(), m.module.trim()));
        Ok(Self {
            modules: foldhash::HashMap::default(),
            operator: Operator::open(op, defs, &is_op, false, foldhash::HashMap::default()),
        })
    }
}

impl AuthMiddleware {
    pub fn new(
        cfg: &AuthCfg,
        registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        Self::build_on(cfg, registry.as_ref(), secret_resolver)
    }

    /// The data chain: `keys` is judged by the chain itself; any other module is refused once its
    /// settings resolve (no `kind: auth` plugin answers it).
    pub fn build_on(
        cfg: &AuthCfg,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        let mut keys_in_chain = false;
        for entry in &cfg.chain {
            match entry.module.as_str() {
                crate::config::KEYS_MODULE => {
                    keys_in_chain = true;
                }
                // The built-in member `anonymous` opens no plugin and reads no credential: the
                // native data chain admits it (`NativeChain::data_with`) under its binding.
                crate::auth::native_chain::ANONYMOUS => {}
                other => {
                    instances::provider_settings(
                        cfg,
                        entry.name.as_str(),
                        other,
                        &entry.settings,
                        registry,
                        secret_resolver,
                        |e| format!("auth.chain module '{other}' settings: {e}"),
                    )?;
                    return Err(format!(
                        "auth.chain module '{other}' could not be loaded as a `kind: auth` \
                         plugin: no `kind: auth` plugin answers to '{other}'"
                    ));
                }
            }
        }

        if !keys_in_chain {
            diag_warn!(
                AUTH_CHAIN_OPEN_RELAY,
                "auth.chain is empty (open relay) - only acceptable for dev; reject in production"
            );
        }

        Ok(Self {
            keys_in_chain,
            chain: Vec::new(),
            readers: Vec::new(),
            reader_by_carrier: foldhash::HashMap::default(),
            carriers: Vec::new(),
            issued: None,
        })
    }

    pub fn chain_names(&self) -> Vec<String> {
        self.chain.iter().map(|e| e.name.clone()).collect()
    }

    /// Effective authentication arms in execution order, including built-in keys.
    pub fn effective_chain_names(&self) -> Vec<String> {
        let mut names = self.chain_names();
        if self.keys_in_chain {
            names.push(crate::config::KEYS_MODULE.to_string());
        }
        names
    }

    #[must_use]
    pub fn position_calls(&self, provider: &str) -> Option<std::sync::Arc<dyn AuthCalls>> {
        self.chain
            .iter()
            .find(|e| e.provider == provider)
            .map(|e| std::sync::Arc::clone(&e.calls))
    }

    /// The instances the chain holds for `provider` (all, for `None`), in chain order: the admin
    /// flush refreshes each distinct one once ([`instances::flush_distinct`]).
    pub(crate) fn chain_instances<'a>(
        &'a self,
        provider: Option<&'a str>,
    ) -> impl Iterator<Item = &'a std::sync::Arc<dyn AuthCalls>> + 'a {
        self.chain
            .iter()
            .filter(move |e| provider.is_none_or(|m| e.provider == m))
            .map(|e| &e.calls)
    }
}

/// The admin plane's verify request for one admin call: the head as presented, no credential.
pub(crate) fn admin_head(
    method: &str,
    target: &str,
    headers: &HeaderMap,
    now: u64,
) -> busbar_contract::auth_calls::VerifyRequest {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (target, None),
    };
    let authority = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    busbar_contract::auth_calls::VerifyRequest {
        point: busbar_contract::route::AuthPoint::Head,
        lines: (headers.iter())
            .map(|(n, v)| {
                let value = busbar_contract::redacted::Secret::new(v.as_bytes().to_vec());
                (n.as_str().to_string(), value)
            })
            .collect(),
        method: method.to_string(),
        authority: authority.to_string(),
        path: path.to_string(),
        query,
        timestamp: now,
        conn: 0,
        unit: 0,
        credential: None,
        peer: None,
        body: None,
    }
}

/// [`admin_head`] carrying the presented admin `candidate` credential.
pub(crate) fn admin_head_with(
    method: &str,
    target: &str,
    headers: &HeaderMap,
    now: u64,
    candidate: Option<&str>,
) -> busbar_contract::auth_calls::VerifyRequest {
    let mut head = admin_head(method, target, headers, now);
    head.credential =
        candidate.map(|c| busbar_contract::redacted::Secret::new(c.as_bytes().to_vec()));
    head
}

/// The admin verbs `principal` holds by name under `module`'s role bindings, capped by `cap`.
pub(crate) fn admin_verbs_named(
    bindings: &crate::config::RoleBindings,
    module: &str,
    principal: &Principal,
    cap: Option<busbar_contract::authz::Scope>,
    rung_of: &impl Fn(&str) -> Option<busbar_contract::authz::Scope>,
) -> std::collections::BTreeSet<String> {
    let Some(table) = bindings.get(module) else {
        return std::collections::BTreeSet::new();
    };
    (principal.roles.iter())
        .filter_map(|role| table.get(role))
        .filter_map(|b| match b.verb_grant() {
            Some(Ok(crate::config::VerbGrant::Named(names))) => Some(names),
            _ => None,
        })
        .flatten()
        .filter(|verb| {
            rung_of(verb.as_str()).is_some_and(|rung| cap.is_none_or(|c| c.allows(rung)))
        })
        .collect()
}

// --- The admin chain's built-in `keys` position and the scope a key or module earns: the admin
// plane's verdict (the node's configuration plane, not the data path). ---

/// The principal an admin key is: `key:<id>` (ADMIN-API r5 section 2.1).
pub(crate) fn admin_key_principal(key: &crate::governance::VirtualKey) -> Principal {
    Principal {
        id: format!("key:{}", key.id),
        name: Some(key.name.clone()),
        roles: Vec::new(),
        ttl_secs: None,
    }
}

/// The admin chain's `keys` position: a busbar-signed key credential carried as the bearer,
/// verified as the data plane's `keys` verifier does, and admitted only when the
/// key holds an `admin` grant. A key without one is a data-plane key and is refused here
/// (`credential_invalid`), exactly as an admin key is refused by the data plane's Approve step.
pub(crate) fn admin_keys_arm(app: &crate::state::App, headers: &HeaderMap, now: u64) -> KeysAdmin {
    let Some(token) = carried_named([AUTHORIZATION.as_str()], headers)
        .filter(|t| t.starts_with(crate::governance::signing::TOKEN_PREFIX))
    else {
        return KeysAdmin::Absent;
    };
    let Some(gov) = app.governance.as_deref() else {
        return KeysAdmin::Refused("credential_invalid");
    };
    match gov.verify_token(token, now, None) {
        Some(key) if key.admin.is_some() => KeysAdmin::Identified(ChainVerdict::Identified {
            module: busbar_contract::kept::Text::fixed(crate::config::KEYS_MODULE),
            principal: admin_key_principal(&key),
            resolved: Some(key),
            signed_authority: None,
        }),
        Some(_) => KeysAdmin::Refused("credential_invalid"),
        None => KeysAdmin::Refused(gov.token_refusal(token, now, None)),
    }
}

pub(crate) fn module_scope_cap(
    caps: &std::collections::HashMap<String, String>,
    operator: &Operator,
    module: &str,
) -> Option<busbar_contract::authz::Scope> {
    use busbar_contract::authz::Scope;
    if operator.is(module) {
        return None;
    }
    Some(
        caps.get(module)
            .map(String::as_str)
            .and_then(Scope::parse)
            .unwrap_or(Scope::ReadOnly),
    )
}

/// The door a key holding an `admin` grant opens (ADMIN-API r5 section 2.1). The scope is the
/// ceiling: with no verbs named the key holds every verb within it (the rung alone); with verbs
/// named it holds exactly those, each only when the closed table declares it and its rung is
/// within the ceiling. A scope the grant spells otherwise is read as `read-only`.
pub(crate) fn admin_door_of_key(
    principal: Principal,
    key: &crate::governance::VirtualKey,
    rung_of: &impl Fn(&str) -> Option<busbar_contract::authz::Scope>,
) -> AdminDoor {
    use busbar_contract::authz::{Grants, Scope};
    let Some(grant) = key.admin.as_ref() else {
        return AdminDoor::Denied;
    };
    let ceiling = Scope::parse(&grant.scope).unwrap_or(Scope::ReadOnly);
    if grant.verbs.is_empty() {
        return AdminDoor::Identified(principal, Grants::of(ceiling));
    }
    let named: std::collections::BTreeSet<String> = (grant.verbs.iter())
        .filter(|verb| rung_of(verb.as_str()).is_some_and(|rung| ceiling.allows(rung)))
        .cloned()
        .collect();
    let reach = (named.iter())
        .filter_map(|verb| rung_of(verb.as_str()))
        .fold(Grants::default(), Grants::with);
    AdminDoor::Listed(
        principal,
        reach,
        VerbAllowList {
            rungs: Grants::default(),
            named,
        },
    )
}
