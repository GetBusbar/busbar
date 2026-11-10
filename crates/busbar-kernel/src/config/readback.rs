// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Safe readback of one resolved configuration generation. This is deliberately a projection,
//! never serialization of `RootCfg`, raw plane documents, or resolved secret material.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Map, Value};

pub use super::authored_routing::AuthoredRouting;
use super::{PluginsCfg, RootCfg};

/// Owned values are copied only after their disclosure policy has been established. A view says
/// what a generation was configured with, not which sockets, runtime or Store are physically active.
#[derive(Clone, Debug, Serialize)]
pub struct ConfiguredView {
    /// Private comparison digests only; never expose policy material or a reusable source document.
    #[serde(skip)]
    pub(crate) security_digest: [u8; 32],
    #[serde(skip)]
    pub(crate) deployment_security_digest: [u8; 32],
    pub meaning: &'static str,
    pub sections: BTreeMap<String, Value>,
    /// Boot-only source facts that resolution does not retain. Absence here must not be read as
    /// an absent/default setting in the operator's document.
    pub unavailable_from_resolved: Vec<&'static str>,
}

impl ConfiguredView {
    /// Capture source-only public facts while the composition transaction still owns its parsed
    /// documents. Opaque filenames and catalog URL/options remain presence/name projections.
    pub fn capture_documents(
        app: &mut crate::state::App,
        deploy: &super::DeployCfg,
        catalog: &std::collections::HashMap<String, super::ProviderDef>,
    ) {
        app.document_source_fingerprints = deploy.document_source_fingerprints;
        let Some(view) = app.configured_view.as_mut() else {
            return;
        };
        let view = std::sync::Arc::make_mut(view);
        view.deployment_security_digest = super::security_policy::digest(&json!({
            "admin_require_mtls": deploy.admin_require_mtls,
        }));
        view.sections.insert(
            "config".into(),
            json!({
                "locked": deploy.config.locked,
            }),
        );
        view.sections.insert(
            "providers_file".into(),
            json!({
                "configured": deploy.providers_file.is_some(),
                "process_override": app.providers_override.is_some(),
            }),
        );
        view.sections.insert(
            "provider_catalog".into(),
            json!({
                "names": catalog.keys().collect::<std::collections::BTreeSet<_>>(),
                "values": "hidden",
                "public": catalog.iter().map(|(name, def)| (name, catalog_provider_view(def))).collect::<BTreeMap<_, _>>(),
            }),
        );
        view.sections.insert(
            "admin_require_mtls".into(),
            json!(deploy.admin_require_mtls),
        );
        if let Some(Value::Object(advanced)) = view.sections.get_mut("advanced") {
            advanced.insert(
                "worker_threads".into(),
                json!(deploy.advanced.worker_threads),
            );
        }
        // Provider protocol options are carried opaquely after resolution. Read only the
        // host's typed authored override here; the catalog's typed protocol is shown separately.
        if let Some(Value::Object(providers)) = view.sections.get_mut("providers") {
            for (name, provider) in providers {
                provider["protocol_override"] =
                    json!(deploy.providers.get(name).and_then(|p| p.protocol.as_ref()));
            }
        }
        if let Some(Value::Object(pools)) = view.sections.get_mut("pools") {
            pools.insert(
                "authored".into(),
                deploy
                    .authored_routing
                    .as_ref()
                    .and_then(|routing| serde_json::to_value(routing).ok())
                    .unwrap_or_else(|| json!({"state":"unavailable"})),
            );
        }
        view.unavailable_from_resolved.clear();
    }

    #[must_use]
    pub fn from_root(cfg: &RootCfg, plugins: &PluginsCfg) -> Self {
        let mut sections = BTreeMap::new();
        macro_rules! put {
            ($key:literal, $value:expr) => {
                sections.insert($key.into(), json!($value));
            };
        }
        put!("listen", cfg.listen);
        // The public origin is validated at boot; nevertheless do not project URL text here:
        // URLs and other opaque strings can contain credentials even outside userinfo.
        put!("public_url", presence(cfg.public_url.is_some()));
        put!("admin_listen", cfg.admin_listen);
        put!("tls", tls_view(cfg.tls.as_ref()));
        put!("admin_tls", tls_view(cfg.admin_tls.as_ref()));
        put!("per_request_fee", cfg.per_request_fee);
        put!("rate_card", cfg.rate_card);
        put!("groups", cfg.groups);
        put!(
            "security",
            json!({
                "blocked_metadata_hosts": cfg.blocked_metadata_hosts,
                "allow_metadata_hosts": cfg.allow_metadata_hosts,
                "allow_all_metadata": cfg.allow_all_metadata,
            })
        );

        let l = &cfg.limits;
        macro_rules! fields {
            ($($field:ident),+ $(,)?) => {
                {
                    let mut fields = Map::new();
                    $(fields.insert(stringify!($field).into(), json!(l.$field));)+
                    Value::Object(fields)
                }
            };
        }
        put!(
            "limits",
            fields!(
                upstream_request_timeout_secs,
                request_body_max_bytes,
                datagram_line_memory_bytes,
                pool_max_idle_per_host,
                pool_idle_timeout_secs,
                max_inbound_concurrent,
                max_keys_per_principal,
                max_auto_provisioned_groups,
                hook_content_max_bytes,
                hard_down_cooldown_secs,
                upstream_error_body_max_bytes,
                tls_handshake_timeout_secs,
                request_body_read_timeout_secs,
                max_honored_retry_after_secs,
                default_max_tokens,
                reasoning_effort_budgets,
            )
        );
        put!(
            "advanced",
            json!({
                "rate_sweep_interval": l.rate_sweep_interval,
                "usage_flush_interval_ms": l.usage_flush_interval_ms,
                "upstream_http1_only": l.upstream_http1_only,
                "upstream_h2_prior_knowledge": l.upstream_h2_prior_knowledge,
                "block_private_addresses": cfg.guard.block_private_addresses,
                "allow_destinations": presence(!cfg.guard.allow.is_empty()),
            })
        );
        put!(
            "health",
            fields!(default_probe_interval_secs, default_probe_timeout_secs)
        );
        put!("routing", fields!(default_policy_timeout_ms));
        put!("export_limits", fields!(key_gauge_limit));

        put!(
            "store",
            cfg.store
                .as_ref()
                .map(|s| plugin_view(&s.module, &s.settings))
        );
        let secrets: BTreeMap<_, _> = cfg
            .secrets
            .iter()
            .map(|(name, def)| (name, plugin_view(name, &def.settings)))
            .collect();
        put!("secrets", secrets);
        put!(
            "identity-providers",
            identities_view(&cfg.identity_providers)
        );
        put!(
            "auth",
            json!({
                "present": cfg.auth.is_some(),
                "chain": cfg.auth.as_ref().map(|a| a.chain.iter().map(|e| &e.name).collect::<Vec<_>>()),
                "admin_auth": cfg.admin_auth,
                "role_bindings": cfg.auth.as_ref().map(|auth| role_bindings_view(&auth.role_bindings)),
                "other_fields": "hidden",
            })
        );
        put!("credentials", presence(cfg.credentials.at_rest.is_some()));
        put!("oauth_as", presence(cfg.oauth_as.is_some()));

        put!("export", exporters_view(&cfg.export_defs));
        put!("hooks", hooks_view(&cfg.hooks));
        put!("global_hooks", cfg.global_hooks);

        // No provider URL, credential reference or plane-owned value is serialized. The names of
        // opaque provider options explain coverage without retaining any of their values.
        let providers: BTreeMap<_, _> = cfg
            .providers
            .iter()
            .map(|(name, p)| {
                (
                    name,
                    json!({
                        "base_url": presence(true),
                        "api_key": presence(!p.api_key.is_none()),
                        "token_url": presence(p.token_url.is_some()),
                        "path": presence(p.path.is_some()),
                        "path_base": presence(p.path_base.is_some()),
                        "health": presence(p.health.is_some()),
                        "health_config": health_view(p.health.as_ref()),
                        "auth_style": p.auth.as_ref().map(super::ProviderAuth::as_str),
                        "allow_metadata_hosts": p.allow_metadata_hosts,
                        "scope": presence(p.scope.is_some()),
                        "subject": presence(p.subject.is_some()),
                        "opaque_keys": p.table.keys().collect::<Vec<_>>(),
                    }),
                )
            })
            .collect();
        put!("providers", providers);
        let models: BTreeMap<_, _> = cfg.models.iter().map(|(name, m)| (name, json!({
            "provider": m.provider, "max_requests": m.max_requests,
            "max_concurrent": m.max_concurrent, "default_max_tokens": m.default_max_tokens,
            "upstream_model": m.upstream_model, "attempt_timeout_ms": m.attempt_timeout_ms,
            "reasoning": m.reasoning, "prompt_caching": m.prompt_caching,
            "protocol": m.protocol,
        }))).collect();
        put!("models", models);
        put!(
            "pools",
            json!({"names": sorted_names(cfg.pools.keys()), "values": "hidden",
                "authored":{"state":"unavailable"},
                "definitions": cfg.pools.iter().map(|(name, pool)| (name, pool_view(pool))).collect::<BTreeMap<_, _>>()})
        );
        put!(
            "plane_sections",
            cfg.plane_sections
                .iter()
                .map(|name| (*name, presence(true)))
                .collect::<BTreeMap<_, _>>()
        );
        put!(
            "plugins",
            json!({
                "enabled": plugins.enabled, "dir": plugins.dir,
                "min_versions": plugins.min_versions,
                "trust": {
                    "allow_unsigned": plugins.trust.allow_unsigned,
                    "allow_third_party": plugins.trust.allow_third_party,
                    "publishers": plugins.trust.publishers.iter().map(|p| json!({
                        "name": p.name, "public_key": p.public_key,
                    })).collect::<Vec<_>>(),
                },
                "fetch": {"count": plugins.fetch.len(), "values": "hidden"},
                "logs": {
                    "dir": plugins.logs.dir, "level": plugins.logs.level,
                    "levels": plugins.logs.levels, "rotate_mb": plugins.logs.rotate_mb,
                    "keep": plugins.logs.keep,
                },
            })
        );
        Self {
            security_digest: super::security_policy::root_digest(cfg, plugins),
            deployment_security_digest: [0; 32],
            meaning: "generation_configured_not_physical_activation",
            sections,
            unavailable_from_resolved: vec![
                "config",
                "providers_file",
                "admin_require_mtls",
                "advanced.worker_threads",
            ],
        }
    }

    /// Refresh definitions changed by clone-and-swap mutations without rebuilding `RootCfg`.
    /// The caller must use the same captured `App` generation for this refresh and its version.
    /// Root configuration values remain the build-time projection, never a fresh disk/Store read.
    pub fn refresh_mutable_registries(&mut self, app: &crate::state::App) {
        self.sections
            .insert("groups".into(), json!(app.groups_registry));
        self.sections
            .insert("hooks".into(), hooks_view(&app.hook_registry));
        self.sections
            .insert("global_hooks".into(), json!(app.global_hooks));
        self.sections.insert(
            "identity-providers".into(),
            identities_view(&app.identity_providers),
        );
        self.sections
            .insert("export".into(), exporters_view(&app.export_defs));
        // PUT admin-auth is a live App clone/swap, not a RootCfg rebuild. Only this known safe
        // member is refreshed; data-auth configuration remains the captured build-time view.
        if let Some(Value::Object(auth)) = self.sections.get_mut("auth") {
            auth.insert("admin_auth".into(), json!(app.admin_chain));
        }
    }
}

// Each projection names its fields explicitly. New config members remain hidden until reviewed.
fn health_view(health: Option<&super::HealthCfg>) -> Value {
    health.map(|h| json!({"mode": h.mode, "interval_secs": h.interval_secs, "timeout_secs": h.timeout_secs})).unwrap_or(Value::Null)
}

fn catalog_provider_view(def: &super::ProviderDef) -> Value {
    json!({
        "protocol": def.protocol,
        "auth_style": def.auth.as_ref().map(super::ProviderAuth::as_str),
        "health_config": health_view(def.health.as_ref()),
        "allow_metadata_hosts": def.allow_metadata_hosts,
        "base_url": presence(true), "path": presence(def.path.is_some()),
        "path_base": presence(def.path_base.is_some()), "token_url": presence(def.token_url.is_some()),
        "scope": presence(def.scope.is_some()), "subject": presence(def.subject.is_some()),
        "error_map_keys": def.error_map.keys().collect::<std::collections::BTreeSet<_>>(),
        "opaque_keys": def.options.keys().collect::<std::collections::BTreeSet<_>>(),
    })
}

fn role_bindings_view(bindings: &super::RoleBindings) -> Value {
    json!(bindings
        .iter()
        .map(|(provider, roles)| {
            (provider, roles.iter().map(|(role, binding)| {
        let (verbs, verbs_state) = match binding.verb_grant() {
            Some(Ok(super::VerbGrant::All)) => (json!("*"), "present"),
            Some(Ok(super::VerbGrant::Named(names))) => (json!(names), "present"),
            // A malformed value has no safe policy projection. Never copy arbitrary JSON here.
            Some(Err(_)) => (Value::Null, "unavailable"),
            None => (Value::Null, "absent"),
        };
        let mut view = json!({"allowed_pools": binding.allowed_pools, "group": binding.group,
            "admin_scope": binding.admin_scope, "verbs": verbs, "verbs_state": verbs_state});
        for (field, names) in &binding.plane_grants {
            view[field] = json!(names);
        }
        (role, view)
    }).collect::<BTreeMap<_, _>>())
        })
        .collect::<BTreeMap<_, _>>())
}

fn pool_view(pool: &super::PoolCfg) -> Value {
    use super::pools::{AffinityMode, OnExhaustedCfg};
    let members: Vec<_> = pool.members.iter().map(|m| json!({
        "model": m.model, "weight": m.weight, "context_max": m.context_max,
        "tier": m.tier, "attempt_timeout_ms": m.attempt_timeout_ms, "reasoning": m.reasoning,
        "tags": {"count": m.tags.len(), "values": "hidden"},
    })).collect();
    let breaker = pool.breaker.as_ref().map(|b| json!({
        "base_cooldown_secs": b.base_cooldown_secs, "max_cooldown_secs": b.max_cooldown_secs,
        "trip": b.trip.as_ref().map(|t| json!({"mode": t.mode, "window_secs": t.window_secs,
            "threshold": t.threshold, "min_requests": t.min_requests, "consecutive_n": t.consecutive_n})),
    }));
    let exhausted = pool.on_exhausted.as_ref().map(|mode| match mode {
        OnExhaustedCfg::Reject => json!("reject"),
        OnExhaustedCfg::LeastBad => json!("least_bad"),
        OnExhaustedCfg::FallbackPool(name) => json!({"fallback_pool": name}),
        OnExhaustedCfg::Queue { max_ms } => json!({"queue": {"max_ms": max_ms}}),
    });
    json!({
        "members": members, "weights": pool.weights, "tier": pool.tier,
        "attempt_timeout_ms": pool.attempt_timeout_ms, "repeatable": pool.repeatable,
        "upstream_credentials": pool.upstream_credentials, "breaker": breaker,
        "failover": pool.failover.as_ref().map(|f| json!({"timeout_secs": f.timeout_secs,"max_hops": f.max_hops,"exclusions": f.exclusions})),
        "on_exhausted": exhausted,
        "affinity": pool.affinity.as_ref().map(|a| json!({"mode": match a.mode { AffinityMode::Session => "session" }, "header_name": a.header_name})),
        "ordering_strategy": pool.policy.native_name().unwrap_or("weighted"),
        "ordering_explicit": pool.base_named, "gates": pool.gates,
    })
}

fn identities_view(defs: &super::IdentityProviders) -> Value {
    let views: BTreeMap<_, _> = defs
        .iter()
        .map(|(name, def)| {
            let mut view = plugin_view(&def.module, &def.settings);
            view["max_admin_scope"] = json!(def.max_admin_scope);
            view["token"] = presence(def.token.is_some());
            view["browser_login"] = presence(def.browser_login.is_some());
            (name, view)
        })
        .collect();
    json!(views)
}

fn exporters_view(defs: &super::ExportDefs) -> Value {
    let views: BTreeMap<_, _> = defs
        .iter()
        .map(|(name, def)| {
            let mut view = plugin_view(&def.module, &def.settings);
            view["streams"] = json!(def.streams);
            view["fields"] = json!(def.fields);
            view["durable"] = json!(def.durable);
            (name, view)
        })
        .collect();
    json!(views)
}

fn hooks_view(defs: &std::collections::HashMap<String, super::HookCfg>) -> Value {
    let views: BTreeMap<_, _> = defs
        .iter()
        .map(|(name, def)| {
            let mut view = plugin_view(&def.plugin, &def.settings);
            view["kind"] = json!(def.kind);
            view["timeout_ms"] = json!(def.timeout_ms);
            view["priority"] = json!(def.priority);
            view["on_error"] = json!(def.on_error);
            view["prompt"] = json!(def.prompt);
            view["user"] = json!(def.user);
            (name, view)
        })
        .collect();
    json!(views)
}

fn sorted_names<'a>(names: impl Iterator<Item = &'a String>) -> Vec<&'a str> {
    let mut names: Vec<_> = names.map(String::as_str).collect();
    names.sort_unstable();
    names
}

fn presence(present: bool) -> Value {
    json!({"present": present, "value": "hidden"})
}

fn tls_view(tls: Option<&super::TlsCfg>) -> Value {
    match tls {
        None => presence(false),
        Some(tls) => json!({
            "present": true, "cert": presence(true), "key": presence(true),
            "client_ca": presence(tls.client_ca.is_some()),
        }),
    }
}

fn plugin_view(module: &str, settings: &busbar_contract::plugin_settings::Settings) -> Value {
    plugin_view_with(module, settings, &super::settings_public::public(module))
}

fn plugin_view_with(
    module: &str,
    settings: &busbar_contract::plugin_settings::Settings,
    public: &std::collections::BTreeSet<String>,
) -> Value {
    json!({
        "module": module,
        "settings_keys": settings.key_names(),
        "settings_public": settings.snapshot_view(public, &super::secret::sugars()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn opaque_settings_are_never_copied_and_public_references_stay_hidden() {
        let settings = json!({
            "timeout": 42,
            "opaque": "RAW_SENTINEL",
            "token": "TOKEN_SENTINEL",
            "reference": {"module": "vault", "settings": {"text": "REF_SENTINEL"}},
            "nested": [{"env": "ENV_SENTINEL"}],
        });
        let public: BTreeSet<_> = ["timeout", "token", "reference", "nested"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let view = plugin_view_with(
            "example",
            &crate::config::secret::test_settings(settings.as_object().unwrap()),
            &public,
        );
        assert_eq!(view["settings_public"], json!({"timeout": 42}));
        let encoded = serde_json::to_string(&view).unwrap();
        for sentinel in [
            "RAW_SENTINEL",
            "TOKEN_SENTINEL",
            "REF_SENTINEL",
            "ENV_SENTINEL",
        ] {
            assert!(!encoded.contains(sentinel));
        }
        assert_eq!(view["settings_keys"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn absent_public_schema_discloses_only_keys() {
        let settings = json!({"url": "URL_SENTINEL", "enabled": true});
        let view = plugin_view_with(
            "unknown",
            &crate::config::secret::test_settings(settings.as_object().unwrap()),
            &BTreeSet::new(),
        );
        assert_eq!(view["settings_public"], json!({}));
        assert!(!format!("{view:?}").contains("URL_SENTINEL"));
    }

    #[test]
    fn tls_is_presence_only_including_secret_reference_settings() {
        let tls = super::super::TlsCfg {
            cert: super::super::SecretRef::template("CERT_SENTINEL"),
            key: super::super::SecretRef::template("KEY_SENTINEL"),
            client_ca: None,
        };
        let view = tls_view(Some(&tls));
        assert_eq!(view["present"], true);
        assert_eq!(view["client_ca"]["present"], false);
        let encoded = serde_json::to_string(&view).unwrap();
        assert!(!encoded.contains("SENTINEL"));
    }
    #[test]
    fn public_role_readback_preserves_grant_tristate_without_raw_json() {
        let mut bindings: super::super::RoleBindings = serde_json::from_value(json!({
            "identity": {
                "unbounded": {"admin_scope":"read-only", "verbs":["get_info"]},
                "denied": {"allowed_pools":[], "group":"team"},
                "specific": {"allowed_pools":["primary"], "verbs":"*", "allowed_tools":["search"]}
            }
        }))
        .unwrap();
        let view = role_bindings_view(&bindings);
        assert_eq!(view["identity"]["unbounded"]["allowed_pools"], Value::Null);
        assert_eq!(view["identity"]["denied"]["allowed_pools"], json!([]));
        assert_eq!(
            view["identity"]["specific"]["allowed_pools"],
            json!(["primary"])
        );
        assert_eq!(
            view["identity"]["specific"]["allowed_tools"],
            json!(["search"])
        );
        assert_eq!(view["identity"]["specific"]["verbs"], "*");
        bindings
            .get_mut("identity")
            .unwrap()
            .get_mut("specific")
            .unwrap()
            .verbs = Some(json!({"opaque":"VERB_SECRET_CANARY"}));
        assert!(!role_bindings_view(&bindings)
            .to_string()
            .contains("VERB_SECRET_CANARY"));
    }

    #[test]
    fn public_pool_readback_exposes_typed_routing_without_opaque_tags() {
        let pool: super::super::PoolCfg = serde_json::from_value(json!({
            "members":[{"model":"m", "weight":3,"context_max":4096,"attempt_timeout_ms":50,"reasoning":true,"tags":["TAG_SECRET_CANARY"]}],
            "weights":{"m":7}, "tier":"small", "attempt_timeout_ms":100,
            "hooks":[{"strategy":"fastest"},"guard"],
            "repeatable":["search"],"upstream_credentials":"own",
            "breaker":{"base_cooldown_secs":4,"max_cooldown_secs":8,"trip":{"mode":"consecutive","consecutive_n":2}},
            "failover":{"timeout_secs":2,"max_hops":1,"exclusions":["spare"]},
            "on_exhausted":{"queue":{"max_ms":100}},
            "affinity":{"mode":"session","header_name":"x-session-id"}
        })).unwrap();
        let view = pool_view(&pool);
        assert_eq!(view["members"][0]["weight"], 3);
        assert_eq!(
            view["members"][0]["tags"],
            json!({"count":1,"values":"hidden"})
        );
        assert_eq!(view["weights"]["m"], 7);
        assert_eq!(view["ordering_strategy"], "fastest");
        assert_eq!(view["ordering_explicit"], true);
        assert_eq!(view["gates"], json!(["guard"]));
        assert_eq!(view["breaker"]["trip"]["consecutive_n"], 2);
        assert_eq!(view["on_exhausted"]["queue"]["max_ms"], 100);
        assert!(!view.to_string().contains("TAG_SECRET_CANARY"));
    }

    #[test]
    fn public_catalog_readback_keeps_urls_references_and_options_hidden() {
        let def = super::super::ProviderDef {
            protocol: "dialect".into(),
            base_url: "https://BASE_SECRET_CANARY".into(),
            error_map: std::collections::HashMap::from([(
                "429".into(),
                "ERROR_SECRET_CANARY".into(),
            )]),
            health: Some(super::super::HealthCfg {
                mode: super::super::HealthMode::Dead,
                interval_secs: Some(10),
                timeout_secs: Some(3),
            }),
            path: Some("PATH_SECRET_CANARY".into()),
            path_base: None,
            token_url: Some("https://TOKEN_SECRET_CANARY".into()),
            scope: Some("SCOPE_SECRET_CANARY".into()),
            subject: Some("SUBJECT_SECRET_CANARY".into()),
            auth: Some(super::super::ProviderAuth::named("credential-style")),
            allow_metadata_hosts: vec!["169.254.169.254".into()],
            options: serde_json::Map::from_iter([(
                "opaque".into(),
                json!({"literal":"OPTION_SECRET_CANARY"}),
            )]),
        };
        let view = catalog_provider_view(&def);
        assert_eq!(view["protocol"], "dialect");
        assert_eq!(view["auth_style"], "credential-style");
        assert_eq!(view["health_config"]["mode"], "dead");
        assert_eq!(view["health_config"]["interval_secs"], 10);
        assert_eq!(view["base_url"]["present"], true);
        assert_eq!(view["path_base"]["present"], false);
        assert_eq!(view["opaque_keys"], json!(["opaque"]));
        assert!(!view.to_string().contains("SECRET_CANARY"));
    }
}
