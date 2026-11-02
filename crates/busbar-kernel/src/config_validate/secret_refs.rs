// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::RootCfg;
use busbar_contract::plugin_rows::PluginRows;

/// Enumerate EVERY secret reference in the resolved config as `(what, &SecretRef)`, where `what` is
/// the human-readable config path used in error messages. The SINGLE source of truth for which
/// references are secrets: the structural check in `validate_cost_model` and the registry-backed
/// module-existence check in `registry_refusal` (deferred until the plugin registry exists)
/// both walk this list, so a new secret-bearing field is covered by both the moment it is added here.
///
/// Every secret-bearing config field must be visited by credential validation. A missing reference must fail validation before runtime, including `identity-providers.<name>.browser_login.client_secret`, which the core presents during confidential-client code-to-token exchange. Exhaustive typed traversal prevents a field from being silently skipped by a hand-maintained path list.
///
///
///
///
///
///
///
/// TWO LAYERS NOW MAKE OMISSION IMPOSSIBLE RATHER THAN REMEMBERED, because each layer catches a
/// different way of introducing one:
///
/// 1. A NEW FIELD ON A TYPE ALREADY WALKED HERE is a COMPILE ERROR. Every struct below is taken
///    apart with an EXHAUSTIVE destructure and no `..`, the idiom already used by
///    `RootSettings::is_empty` and `config::patch`. Adding a field to `RootCfg`, `TlsCfg`,
///    `AuthCfg`, `AuthChainEntry`, `AuthMethodCfg`, `BrowserLoginCfg`, `IdentityProviderCfg`,
///    `CredentialsCfg`, `AtRestCfg` or `ResolvedProvider` fails to build with `E0027 pattern does not mention field` until somebody has
///    decided, here, whether it carries a secret.
/// 2. A NEW SECRET-BEARING TYPE is a TEST failure. The compiler cannot help with a `SecretRef`
///    added to a struct this function never destructures, so
///    `config_validate::tests::secret_ref_coverage` reads the crate's own sources, finds every
///    field anywhere in the tree whose type mentions `SecretRef`, and requires the declaring type to
///    appear in [`SECRET_BEARING_TYPES`] below. A new one fails the test with the type named.
pub(crate) fn secret_refs(cfg: &RootCfg) -> Vec<(String, &crate::config::SecretRef)> {
    walk_secret_refs(cfg, TokenRefs::Every)
}

pub(crate) fn keyless_credential_allowed(what: &str) -> bool {
    what.starts_with("providers.") && what.ends_with(".api_key")
}

pub(crate) fn boot_resolved_secret_refs(cfg: &RootCfg) -> Vec<(String, &crate::config::SecretRef)> {
    walk_secret_refs(cfg, TokenRefs::BootResolved)
}

pub(crate) fn secret_module(registry: &dyn PluginRows, module: &str) -> Result<String, String> {
    match registry.resolve(module) {
        Some(p) if p.kind == "secret" => Ok(p.key),
        Some(p) => Err(format!(
            "secrets.{module}: plugin '{}' has kind '{}', not 'secret'; only a kind: secret plugin \
             can back a `secrets:` block entry",
            p.key, p.kind
        )),
        None => Err(format!(
            "secrets.{module}: no loadable `kind: secret` plugin is named or aliased '{module}' \
             (check the spelling against the plugin's manifest name/alias, and that the plugin \
             loaded — see --list-plugins)"
        )),
    }
}

pub(crate) fn registry_refusal(registry: &dyn PluginRows, cfg: &RootCfg) -> Result<(), String> {
    registry_refusal_with(registry, cfg, crate::config::secret::axis())
}

pub(crate) fn registry_refusal_with(
    registry: &dyn PluginRows,
    cfg: &RootCfg,
    axis: Option<&dyn busbar_contract::secret::SecretAxis>,
) -> Result<(), String> {
    for module in cfg.secrets.keys() {
        secret_module(registry, module)?;
    }
    for (what, r) in secret_refs(cfg) {
        if r.is_none() {
            continue;
        }
        if let Some(axis) = axis.filter(|a| a.answers(&r.module)) {
            let settings = serde_json::Value::Object(r.settings.clone());
            if let Err(reasons) = axis.check(&r.module, &settings) {
                return Err(reasons
                    .iter()
                    .map(|line| format!("{what}: {line}"))
                    .collect::<Vec<_>>()
                    .join("\n"));
            }
        }
        if axis.is_some_and(|a| a.linked(&r.module)) {
            continue;
        }
        match registry.resolve(&r.module) {
            Some(p) if p.kind == "secret" => {}
            Some(p) => {
                return Err(format!(
                    "{what} references secret module '{}', but plugin '{}' has kind '{}', not \
                     'secret'; only a `kind: secret` plugin can back a secret reference",
                    r.module, p.key, p.kind
                ));
            }
            None => {
                return Err(format!(
                    "{what} references secret module '{}', which is not a built-in (`env` | `file`) \
                     and no loadable `kind: secret` plugin is named or aliased '{}'. Fix the \
                     spelling, install/trust the plugin (see --list-plugins), or use a built-in, \
                     e.g.:\n\n    {what}: {{ env: MY_SECRET_VAR }}\n",
                    r.module, r.module
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn builtins_resolve(cfg: &RootCfg) -> Result<(), String> {
    let builtins = crate::config::secret::SecretResolver::builtins_only();
    for (what, r) in boot_resolved_secret_refs(cfg) {
        if !crate::config::secret::is_linked_secret(&r.module) {
            continue;
        }
        if let Err(e) =
            builtins.resolve_at_config(r, &busbar_contract::config_time::ConfigScope::config_time())
        {
            return Err(format!("{what}: {e}"));
        }
    }
    Ok(())
}

/// Which identity-provider `token:` references a walk reports. See [`boot_resolved_secret_refs`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenRefs {
    /// Every `token:` in the config: on each `identity-providers:` definition and on each resolved
    /// chain entry. The coverage contract — nothing that can hold a secret is skipped.
    Every,
    /// Only the one `token:` boot resolves (the operator credential from the resolved chains).
    BootResolved,
}

fn walk_secret_refs(cfg: &RootCfg, tokens: TokenRefs) -> Vec<(String, &crate::config::SecretRef)> {
    let boot_token = cfg.auth.as_ref().and_then(|auth| auth.admin_token_ref());
    walk_secret_refs_with_boot_token(cfg, tokens, boot_token)
}

fn walk_secret_refs_with_boot_token<'a>(
    cfg: &'a RootCfg,
    tokens: TokenRefs,
    boot_token: Option<&crate::config::SecretRef>,
) -> Vec<(String, &'a crate::config::SecretRef)> {
    let RootCfg {
        tls,
        admin_tls,
        auth,
        providers,
        identity_providers,
        credentials,

        listen: _,
        public_url: _,
        admin_listen: _,
        admin_auth: _,
        global_hooks: _,

        groups: _,
        rate_card: _,
        per_request_fee: _,
        plane_fees: _,
        limits: _,
        blocked_metadata_hosts: _,
        allow_metadata_hosts: _,
        allow_all_metadata: _,
        guard: _,
        upstream_credentials: _,

        plane_sections: _,

        store: _,
        secrets: _,
        hooks: _,
        export: _,
        export_defs: _,

        models: _,
        pools: _,

        endpoint_resources: _,

        oauth_as,

        plane_defs,

        plane_pools: _,
    } = cfg;

    let mut refs: Vec<(String, &crate::config::SecretRef)> = Vec::new();

    if let Some(crate::oauth_as::seam::CheckedAsBlock {
        block: _,
        secret_refs,
    }) = oauth_as
    {
        refs.extend(secret_refs.iter().map(|(path, key)| (path.clone(), key)));
    }

    let crate::config::CredentialsCfg { at_rest } = credentials;
    if let Some(crate::config::AtRestCfg { key, previous }) = at_rest {
        refs.push(("credentials.at_rest.key".to_string(), key));
        if let Some(previous) = previous {
            refs.push(("credentials.at_rest.previous".to_string(), previous));
        }
    }

    for (name, p) in providers {
        let crate::config::ResolvedProvider {
            api_key,

            base_url: _,
            health: _,
            path: _,
            path_base: _,
            token_url: _,
            scope: _,
            subject: _,
            auth: _,
            allow_metadata_hosts: _,
            table: _,
        } = p;
        refs.push((format!("providers.{name}.api_key"), api_key));
    }
    push_tls_refs(&mut refs, "tls", tls.as_ref());
    push_tls_refs(&mut refs, "admin_tls", admin_tls.as_ref());

    for (name, def) in identity_providers {
        let crate::config::IdentityProviderCfg {
            token,
            browser_login,
            module: _,
            max_admin_scope: _,
            settings: _,
        } = def;

        if let (Some(tok), TokenRefs::Every) = (token, tokens) {
            refs.push((format!("identity-providers.{name}.token"), tok));
        }
        push_browser_login_refs(
            &mut refs,
            &format!("identity-providers.{name}"),
            browser_login.as_ref(),
        );
    }

    if let Some(auth) = auth {
        let crate::config::AuthCfg {
            signing_key,
            chain,
            admin_auth,
            methods,

            role_bindings: _,

            key_ttl: _,

            policy: _,
        } = auth;
        if let Some(sk) = signing_key {
            refs.push(("auth.signing_key".to_string(), sk));
        }

        for (plane, entries) in [("chain", chain), ("admin_auth", admin_auth)] {
            for entry in entries {
                let crate::config::AuthChainEntry {
                    token,
                    name,
                    module: _,
                    max_admin_scope: _,
                    settings: _,
                } = entry;
                if let Some(tok) = token {
                    let reported = match tokens {
                        TokenRefs::Every => true,
                        TokenRefs::BootResolved => boot_token.is_some_and(|b| std::ptr::eq(b, tok)),
                    };
                    if reported {
                        refs.push((format!("auth.{plane}.{name}.token"), tok));
                    }
                }
            }
        }
        for (name, method) in methods {
            let crate::config::AuthMethodCfg {
                browser_login,
                module: _,
                settings: _,
            } = method;
            push_browser_login_refs(
                &mut refs,
                &format!("auth.methods.{name}"),
                browser_login.as_ref(),
            );
        }
    }

    for plane_cfg in plane_defs.values() {
        refs.extend(plane_cfg.secret_refs());
    }

    refs
}

fn push_tls_refs<'a>(
    refs: &mut Vec<(String, &'a crate::config::SecretRef)>,
    at: &str,
    tls: Option<&'a crate::config::TlsCfg>,
) {
    let Some(tls) = tls else {
        return;
    };
    let crate::config::TlsCfg {
        cert,
        key,
        client_ca,
    } = tls;
    refs.push((format!("{at}.cert"), cert));
    refs.push((format!("{at}.key"), key));
    if let Some(ca) = client_ca {
        refs.push((format!("{at}.client_ca"), ca));
    }
}

fn push_browser_login_refs<'a>(
    refs: &mut Vec<(String, &'a crate::config::SecretRef)>,
    at: &str,
    login: Option<&'a crate::config::BrowserLoginCfg>,
) {
    let Some(login) = login else {
        return;
    };
    let crate::config::BrowserLoginCfg {
        client_secret,

        client_id: _,
    } = login;
    if let Some(secret) = client_secret {
        refs.push((format!("{at}.browser_login.client_secret"), secret));
    }
}

#[cfg(test)]
pub(crate) const SECRET_BEARING_TYPES: &[(&str, SecretBearing)] = &[
    ("TlsCfg", SecretBearing::Walked),
    ("ResolvedProvider", SecretBearing::Walked),
    (
        "ProviderCfg",
        SecretBearing::NotInResolvedConfig(
            "the frozen whole-entry PARSE shape of a provider; it is never part of `RootCfg`. \
             `resolve` lowers a catalog entry and its deployment into `ResolvedProvider`, which IS \
             walked.",
        ),
    ),
    (
        "ProviderCfgCore",
        SecretBearing::NotInResolvedConfig(
            "serde's remote deserialize shape for ProviderCfg; it produces ProviderCfg, which \
             resolve lowers into the walked ResolvedProvider before validation.",
        ),
    ),
    (
        "ProviderDeployCore",
        SecretBearing::NotInResolvedConfig(
            "serde's remote deserialize shape for ProviderDeploy; it produces ProviderDeploy, \
             which resolve lowers into the walked ResolvedProvider before validation.",
        ),
    ),
    ("AuthCfg", SecretBearing::Walked),

    ("AtRestCfg", SecretBearing::Walked),
    ("AuthChainEntry", SecretBearing::Walked),
    ("IdentityProviderCfg", SecretBearing::Walked),
    ("BrowserLoginCfg", SecretBearing::Walked),














    ("CheckedAsBlock", SecretBearing::Walked),


    (
        "DoorSection",
        SecretBearing::DoorDeclared(
            "the folded door row's section: it holds the references read at its door's declared \
             `settings.` paths and answers them through `PlaneCfg::secret_refs`",
        ),
    ),
    (
        "AsIdentity",
        SecretBearing::NotInResolvedConfig(
            "the `oauth_as:` block is OPAQUE in `RootCfg`: the kernel hands it to its owner through \
             the seam's `check`, and `busbar-core-oauth2` walks this type with an exhaustive \
             destructure (`config::secret_refs`), so a new secret field there is a compile error.",
        ),
    ),
    (
        "OauthAsCfg",
        SecretBearing::NotInResolvedConfig(
            "the DESERIALIZE-side `oauth_as:` block. `busbar-core-oauth2` lowers it into \
             `AsIdentity` and walks that, and `resolve` runs that owner check on every \
             `--validate`/boot, so the block is covered without the kernel naming this type.",
        ),
    ),
    (
        "AuthDeployCfg",
        SecretBearing::NotInResolvedConfig(
            "the DESERIALIZE-side `auth:` block. `resolve_auth` lowers it into `AuthCfg`, which IS \
             walked, and every `--validate`/boot check runs against the RESOLVED config.",
        ),
    ),
    (
        "Program",
        SecretBearing::NotInResolvedConfig(
            "a member PROGRAM the host reads off a plane's settings at open and refresh \
             (`busbar_contract::conn::Program`), never a `RootCfg` type: its `env_refs` \
             references are resolved when the need that names the program is declared and on the \
             refresher's lease, with the config-time proof (#865, row 166), and held for its \
             spawns in a `SpawnEnv`; one that does not resolve refuses every spawn, naming the \
             variable.",
        ),
    ),
    (
        "SpawnEnv",
        SecretBearing::NotInResolvedConfig(
            "the connector's HELD environment of one member program (its spawn environment, \
             #865, row 166): a runtime CARRIER built from a \
             `Program`'s `env_refs` when its need is declared, resolved there and on the \
             refresher's lease and never at a spawn; it is never part of `RootCfg`.",
        ),
    ),
    (
        "ProviderDeploy",
        SecretBearing::NotInResolvedConfig(
            "the DESERIALIZE-side provider entry (providers.yaml). `resolve` lowers it into \
             `ResolvedProvider`, which IS walked.",
        ),
    ),
    (
        "ProviderRoute",
        SecretBearing::NotInResolvedConfig(
            "the composition root's copy of a `ResolvedProvider` (`root::door_steps::\
             provider_routes`), made for a door plane's members after the `ResolvedProvider` it \
             copies was walked; it is never part of `RootCfg`.",
        ),
    ),
    (
        "PerHop",
        SecretBearing::NotInResolvedConfig(
            "the composition root's per-hop binding of a registration's own outbound credential \
             (`root::door_steps::upstream_credential_binding`): a runtime CARRIER built from the \
             reference a door section declares at its `settings.*.upstream_credential.secret` path, \
             which the door section's walk (`DoorSection`) already reported; it is never part of \
             `RootCfg`.",
        ),
    ),
];

/// How [`secret_refs`] accounts for one secret-bearing type. See [`SECRET_BEARING_TYPES`].
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretBearing {
    /// Exhaustively destructured by [`secret_refs`], so every one of its `SecretRef` fields reaches
    /// the returned list and a new field is a compile error.
    Walked,
    /// Not reachable from `RootCfg` at all, with the reason it is not.
    ///
    /// Two shapes land here, on either side of the walk. A DESERIALIZE-side config shape that is
    /// LOWERED into a walked type before any validation runs (`OauthAsCfg` -> `AsIdentity`), and a
    /// runtime CARRIER built FROM walked references after the walk has already reported them. Both
    /// are unreachable from `RootCfg`, which is the claim the variant makes and the one the test
    /// checks; each entry's reason says which shape it is and why the references it touches are
    /// covered elsewhere.
    NotInResolvedConfig(&'static str),
    /// A DOOR PLANE'S configuration type: the kernel holds no typed copy of a door's section, so it
    /// never destructures the type; it reads every reference the section holds at the door's
    /// declared secret-reference paths (`PlaneRegistration::secret_refs`), walking the section as
    /// written. The reason names those paths.
    DoorDeclared(&'static str),
}

#[cfg(test)]
#[path = "tests/secret_ref_coverage.rs"]
mod secret_ref_coverage;
