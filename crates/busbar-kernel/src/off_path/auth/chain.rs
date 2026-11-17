// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth chain's off-path code: the data and admin chains, the operator provider and the
//! credential readers built once per configuration load, the admin service's views of them, and
//! the admin plane's verify-request construction and its keys position and scope caps (the node's
//! configuration plane, not the data path). The request path reads only what this builds.

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderName};

use crate::auth::{
    carried_named, instances, AdminAuthChain, AdminDoor, AdminModule, AuthMiddleware, ChainEntry,
    ChainVerdict, CredentialReader, KeysAdmin, Operator, Principal, VerbAllowList,
};
use crate::config::AuthCfg;
use crate::diagnostics::{diag_warn, AUTH_CHAIN_OPEN_RELAY};
use busbar_contract::auth_calls::AuthCalls;

/// How an auth instance's settings are re-resolved for a re-lend: `None` when its plugin lends no
/// secret reference (nothing it holds can rotate).
pub(crate) fn relender(
    settings: &busbar_contract::plugin_settings::Settings,
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
    module: &str,
    resolver: &crate::config::secret::SecretResolver,
) -> Option<crate::auth::relend::Reresolve> {
    let secrets = registry.secret_slots(module);
    if secrets.is_empty() {
        return None;
    }
    let references = registry.reference_slots(module);
    let (settings, module, resolver) = (settings.clone(), module.to_string(), resolver.clone());
    Some(Box::new(move || {
        crate::config::secret::resolve_settings(
            &settings,
            &secrets,
            &references,
            &module,
            &resolver,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
    }))
}

pub(crate) fn auth_refusal(
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
    module: &str,
) -> String {
    registry.kind_refusal(
        busbar_contract::abi::mechanism::kind::AUTH,
        "serve as an auth module",
        module,
    )
}

impl AdminAuthChain {
    pub fn build(
        cfg: &AuthCfg,
        registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        Self::build_on(
            cfg,
            registry.as_ref(),
            secret_resolver,
            &mut instances::AuthInstances::default(),
            &|| crate::preflight::auth_axis(registry.clone()),
        )
    }

    /// [`Self::build`] over the build's shared `instances`: a provider another role already
    /// opened is handed over, not opened again (WASTE-AUTH-SECRETS W1).
    pub(crate) fn build_on(
        cfg: &AuthCfg,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
        instances: &mut instances::AuthInstances,
        open_axis: &dyn Fn() -> Option<std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>>,
    ) -> Result<Self, String> {
        let mut modules: foldhash::HashMap<String, AdminModule> = foldhash::HashMap::default();
        let op = crate::config::operator_provider();
        let is_op = |m: &str| crate::config::names_operator(m);
        let mut axis: Option<std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>> = None;
        let mut opened: foldhash::HashMap<String, std::sync::Arc<dyn AuthCalls>> =
            foldhash::HashMap::default();
        for entry in &cfg.admin_auth {
            let backed = Operator::backed(op, &entry.name, Some(entry.module.as_str()), &is_op);
            match entry.module.as_str() {
                // An operator-backed entry with no settings is unset: nothing opens.
                _ if backed && entry.settings.is_empty() => {}
                // The built-in `keys` position opens no plugin: the admin chain judges it itself.
                crate::config::KEYS_MODULE => {}
                other => {
                    let name = entry.name.as_str();
                    let refused = |e: String| {
                        format!(
                            "auth.admin_auth provider '{name}' (module '{other}') could not be \
                             loaded as a `kind: auth` plugin: {e}"
                        )
                    };
                    let calls = instances.instance(
                        name,
                        other,
                        registry,
                        || {
                            let mut resolved = instances::provider_settings(
                                cfg,
                                name,
                                other,
                                &entry.settings,
                                registry,
                                secret_resolver,
                                |e| format!("identity-providers.{name} settings: {e}"),
                            )?;

                            let axis = match &axis {
                                Some(axis) => axis.clone(),
                                None => {
                                    let opened = open_axis().ok_or_else(|| {
                                        refused(format!(
                                            "no `kind: auth` plugin answers to '{other}'"
                                        ))
                                    })?;
                                    axis.insert(opened).clone()
                                }
                            };

                            if !axis.answers(other) {
                                return Err(refused(auth_refusal(registry, other)));
                            }
                            instances::lend_login_secret(
                                cfg,
                                name,
                                other,
                                registry,
                                secret_resolver,
                                &mut resolved,
                            )?;

                            Ok(instances::Prepared {
                                axis,
                                resolved,
                                reresolve: instances::reresolve(
                                    cfg,
                                    name,
                                    other,
                                    &entry.settings,
                                    registry,
                                    secret_resolver,
                                ),
                            })
                        },
                        refused,
                    )?;

                    // The operator row is an ordinary auth instance opened with its own settings,
                    // judged in the operator arm (OPERATOR-FROM-ADMITTED-AUTH §3.8).
                    if backed {
                        opened.insert(name.to_string(), calls);
                    } else {
                        modules.insert(name.to_string(), AdminModule { calls });
                    }
                }
            }
        }
        let operator_axis = match axis {
            Some(axis) => Some(axis),
            None if op.is_empty() => None,
            None => open_axis(),
        };
        let answered = !op.is_empty() && operator_axis.as_ref().is_some_and(|a| a.answers(op));
        let carriers = match (&operator_axis, answered) {
            (Some(axis), true) => axis.carriers(op),
            _ => Vec::new(),
        };
        let defs = cfg
            .methods
            .iter()
            .map(|(n, m)| (n.as_str(), m.module.trim()));
        Ok(Self {
            modules,
            operator: Operator::open(op, defs, &is_op, answered, opened).with_carriers(carriers),
        })
    }
}

impl AuthMiddleware {
    pub fn new(
        cfg: &AuthCfg,
        registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        Self::build_on(
            cfg,
            registry.as_ref(),
            secret_resolver,
            &mut instances::AuthInstances::default(),
            &|| crate::preflight::auth_axis(registry.clone()),
        )
    }

    /// Build over explicit root-owned auth instances and their complete service-bound axis.
    /// The same instance map is shared by all roles in this generation.
    pub fn build_on(
        cfg: &AuthCfg,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
        instances: &mut instances::AuthInstances,
        open_axis: &dyn Fn() -> Option<std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>>,
    ) -> Result<Self, String> {
        let mut keys_in_chain = false;
        let mut chain: Vec<ChainEntry> = Vec::new();
        let mut axis: Option<std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>> = None;
        for entry in &cfg.chain {
            match entry.module.as_str() {
                crate::config::KEYS_MODULE => {
                    keys_in_chain = true;
                }
                other => {
                    let refused = |e: String| {
                        format!(
                            "auth.chain module '{other}' could not be loaded as a `kind: auth` \
                             plugin: {e}"
                        )
                    };
                    let name = entry.name.as_str();
                    let calls = instances.instance(
                        name,
                        other,
                        registry,
                        || {
                            let mut resolved = instances::provider_settings(
                                cfg,
                                name,
                                other,
                                &entry.settings,
                                registry,
                                secret_resolver,
                                |e| format!("auth.chain module '{other}' settings: {e}"),
                            )?;
                            let axis = match &axis {
                                Some(axis) => axis.clone(),
                                None => {
                                    let opened = open_axis().ok_or_else(|| {
                                        refused(format!(
                                            "no `kind: auth` plugin answers to '{other}'"
                                        ))
                                    })?;
                                    axis.insert(opened).clone()
                                }
                            };

                            if !axis.answers(other) {
                                return Err(refused(auth_refusal(registry, other)));
                            }
                            instances::lend_login_secret(
                                cfg,
                                name,
                                other,
                                registry,
                                secret_resolver,
                                &mut resolved,
                            )?;
                            Ok(instances::Prepared {
                                axis,
                                resolved,
                                reresolve: instances::reresolve(
                                    cfg,
                                    name,
                                    other,
                                    &entry.settings,
                                    registry,
                                    secret_resolver,
                                ),
                            })
                        },
                        refused,
                    )?;
                    chain.push(ChainEntry {
                        provider: entry.name.clone(),
                        name: calls.name().to_string(),
                        calls,
                    });
                }
            }
        }

        if chain.is_empty() && !keys_in_chain {
            diag_warn!(
                AUTH_CHAIN_OPEN_RELAY,
                "auth.chain is empty (open relay) - only acceptable for dev; reject in production"
            );
        }

        let mut readers: Vec<CredentialReader> = Vec::new();
        let mut reader_by_carrier: foldhash::HashMap<HeaderName, usize> =
            foldhash::HashMap::default();
        if keys_in_chain {
            let axis = match &axis {
                Some(axis) => Some(axis.clone()),
                None => open_axis(),
            };
            for module in axis.iter().flat_map(|a| a.credential_readers()) {
                let calls = axis
                    .as_ref()
                    .map(|a| {
                        a.open(
                            &module,
                            &module,
                            &busbar_contract::plugin_settings::ResolvedSettings::default(),
                        )
                    })
                    .transpose()
                    .map_err(|e| {
                        format!(
                            "auth.chain names `keys`, and the `kind: auth` plugin '{module}' that \
                             verifies the credentials it holds could not be loaded: {e}"
                        )
                    })?;
                if let Some(calls) = calls {
                    let index = readers.len();
                    for carrier in calls
                        .carriers()
                        .iter()
                        .filter_map(|c| HeaderName::from_bytes(c.as_bytes()).ok())
                    {
                        reader_by_carrier.entry(carrier).or_insert(index);
                    }
                    let name = std::sync::Arc::<str>::from(module.as_str());
                    let kinds = std::sync::Arc::<[String]>::from(calls.credential_kinds());
                    readers.push(CredentialReader {
                        name,
                        kinds,
                        issued: calls.issued_shape(),
                        calls,
                    });
                }
            }
        }

        let carriers = match &axis {
            Some(axis) => axis.default_inbound_style()?,
            None => open_axis()
                .map(|axis| axis.default_inbound_style())
                .transpose()?
                .unwrap_or_default(),
        };

        let issued = readers
            .iter()
            .find_map(|r| {
                let kind = r.kinds.first()?.clone();
                r.issued.clone().map(|shape| (kind, shape))
            })
            .or_else(|| match &axis {
                Some(axis) => axis.issued_credential(),
                None => open_axis().and_then(|axis| axis.issued_credential()),
            });
        Ok(Self {
            keys_in_chain,
            chain,
            readers,
            reader_by_carrier,
            carriers: header_names(&carriers),
            issued,
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

    pub fn position_points(&self, provider: &str) -> busbar_contract::abi::auth::AuthPoints {
        use busbar_contract::abi::auth::AuthPoints;
        if let Some(entry) = self.chain.iter().find(|e| e.provider == provider) {
            return entry.calls.inbound_points();
        }
        let readers = self
            .readers
            .iter()
            .fold(0, |set, r| set | r.calls.inbound_points().bits());
        if readers == 0 {
            AuthPoints::HEAD
        } else {
            AuthPoints(readers)
        }
    }

    /// The instances the chain holds for `provider` (all, for `None`), in chain order: the admin
    /// flush refreshes each distinct one once ([`instances::flush_distinct`]).
    pub(crate) fn chain_instances<'a>(
        &'a self,
        provider: Option<&'a str>,
    ) -> impl Iterator<Item = &'a std::sync::Arc<dyn AuthCalls>> + 'a {
        self.chain
            .iter()
            .filter(move |e| provider.is_none_or(|m| m == e.provider))
            .map(|e| &e.calls)
    }
}

/// The configured carrier words as header names, parsed once when the chain is built.
pub(crate) fn header_names(words: &[String]) -> Vec<HeaderName> {
    words
        .iter()
        .filter_map(|w| HeaderName::from_bytes(w.as_bytes()).ok())
        .collect()
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
        point: busbar_contract::abi::auth::AuthPoint::Head,
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

/// The admin chain's `keys` position: a busbar-signed key credential carried as the bearer or in
/// `x-admin-token`, verified as the data plane's `keys` verifier does, and admitted only when the
/// key holds an `admin` grant. A key without one is a data-plane key and is refused here
/// (`credential_invalid`), exactly as an admin key is refused by the data plane's Approve step.
pub(crate) fn admin_keys_arm(app: &crate::state::App, headers: &HeaderMap, now: u64) -> KeysAdmin {
    let Some(token) = carried_named([AUTHORIZATION.as_str(), "x-admin-token"], headers)
        .filter(|t| t.starts_with(crate::governance::signing::TOKEN_PREFIX))
    else {
        return KeysAdmin::Absent;
    };
    let Some(gov) = app.governance.as_deref() else {
        return KeysAdmin::Refused("credential_invalid");
    };
    match gov.verify_token(token, now, None) {
        Some(key) if key.admin.is_some() => KeysAdmin::Identified(ChainVerdict::Identified {
            module: crate::config::KEYS_MODULE.to_string(),
            principal: admin_key_principal(&key),
            resolved: Some(key),
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
