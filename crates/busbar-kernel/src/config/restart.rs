// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Private boot-applied configuration comparisons. No readback or serialization of held values.
use super::{DeployCfg, PluginsCfg, RootCfg, SecretModuleCfg, StoreCfg, TlsCfg};
use std::collections::BTreeMap;

#[derive(Clone)]
pub(crate) struct Root {
    listen: String,
    admin_listen: String,
    tls: Option<TlsCfg>,
    admin_tls: Option<TlsCfg>,
    store: Option<StoreCfg>,
    secrets: BTreeMap<String, SecretModuleCfg>,
    plugins: PluginsCfg,
    limits: super::LimitsResolved,
}

fn same_yaml(
    a: &Option<busbar_contract::yaml::Value>,
    b: &Option<busbar_contract::yaml::Value>,
) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => busbar_contract::yaml::same_tree(a, b),
        (None, None) => true,
        _ => false,
    }
}

fn same_store(a: &Option<StoreCfg>, b: &Option<StoreCfg>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            a.module == b.module
                && a.settings == b.settings
                && same_yaml(&a.insecure_transport, &b.insecure_transport)
        }
        (None, None) => true,
        _ => false,
    }
}

fn same_secrets(
    a: &BTreeMap<String, SecretModuleCfg>,
    b: &BTreeMap<String, SecretModuleCfg>,
) -> bool {
    a.len() == b.len()
        && a.iter().all(|(name, a)| {
            b.get(name).is_some_and(|b| {
                a.module == b.module
                    && a.settings == b.settings
                    && same_yaml(&a.insecure_transport, &b.insecure_transport)
            })
        })
}

impl Root {
    pub(crate) fn capture(cfg: &RootCfg, plugins: &PluginsCfg) -> Self {
        Self {
            listen: cfg.listen.clone(),
            admin_listen: cfg.admin_listen.clone(),
            tls: cfg.tls.clone(),
            admin_tls: cfg.admin_tls.clone(),
            store: cfg.store.clone(),
            secrets: cfg.secrets.clone(),
            plugins: plugins.clone(),
            limits: cfg.limits.clone(),
        }
    }

    pub(crate) fn changed(&self, boot: &Self) -> Vec<String> {
        let mut paths = Vec::new();
        macro_rules! changed {
            ($path:literal, $a:expr, $b:expr) => {
                if $a != $b {
                    paths.push($path.to_owned());
                }
            };
        }
        changed!("/listen", self.listen, boot.listen);
        changed!("/admin_listen", self.admin_listen, boot.admin_listen);
        changed!("/tls", self.tls, boot.tls);
        changed!("/admin_tls", self.admin_tls, boot.admin_tls);
        if !same_store(&self.store, &boot.store) {
            paths.push("/store".to_owned());
        }
        if !same_secrets(&self.secrets, &boot.secrets) {
            paths.push("/secrets".to_owned());
        }
        changed!("/plugins", self.plugins, boot.plugins);
        changed!(
            "/limits/upstream_request_timeout_secs",
            self.limits.upstream_request_timeout_secs,
            boot.limits.upstream_request_timeout_secs
        );
        changed!(
            "/limits/pool_max_idle_per_host",
            self.limits.pool_max_idle_per_host,
            boot.limits.pool_max_idle_per_host
        );
        changed!(
            "/limits/pool_idle_timeout_secs",
            self.limits.pool_idle_timeout_secs,
            boot.limits.pool_idle_timeout_secs
        );
        changed!(
            "/limits/max_inbound_concurrent",
            self.limits.max_inbound_concurrent,
            boot.limits.max_inbound_concurrent
        );
        changed!(
            "/advanced/upstream_http1_only",
            self.limits.upstream_http1_only,
            boot.limits.upstream_http1_only
        );
        changed!(
            "/advanced/upstream_h2_prior_knowledge",
            self.limits.upstream_h2_prior_knowledge,
            boot.limits.upstream_h2_prior_knowledge
        );
        paths
    }
}

#[derive(Clone)]
pub(crate) struct Source {
    workers: Option<usize>,
    headers: super::ResponseHeadersCfg,
    admin_mtls: bool,
}

impl Source {
    fn capture(cfg: &DeployCfg) -> Self {
        Self {
            workers: cfg.advanced.worker_threads,
            headers: cfg.advanced.response_headers.clone(),
            admin_mtls: cfg.admin_require_mtls,
        }
    }

    fn changed(&self, boot: &Self) -> Vec<String> {
        let mut paths = Vec::new();
        if self.workers != boot.workers {
            paths.push("/advanced/worker_threads".to_owned());
        }
        if self.headers != boot.headers {
            paths.push("/advanced/response_headers".to_owned());
        }
        if self.admin_mtls != boot.admin_mtls {
            paths.push("/admin_require_mtls".to_owned());
        }
        paths
    }
}

pub(crate) fn capture_documents(app: &mut crate::state::App, cfg: &DeployCfg) {
    let candidate = Source::capture(cfg);
    if let Some(boot) = &app.boot_restart_source {
        app.config_pending_restart.extend(candidate.changed(boot));
        app.config_pending_restart.sort();
        app.config_pending_restart.dedup();
    } else {
        app.boot_restart_source = Some(std::sync::Arc::new(candidate));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> Root {
        Root {
            listen: "127.0.0.1:8080".into(),
            admin_listen: "127.0.0.1:8081".into(),
            tls: None,
            admin_tls: None,
            store: None,
            secrets: BTreeMap::new(),
            plugins: PluginsCfg::default(),
            limits: super::super::LimitsResolved::default(),
        }
    }

    #[test]
    fn boot_listener_changes_are_not_live_limits() {
        let boot = baseline();
        let mut next = boot.clone();
        next.listen = "127.0.0.1:9090".into();
        next.limits.request_body_max_bytes += 1;
        // Removed advanced keys remain refused by config's
        // removed_pre_release_limits_and_drain_keys_are_refused_as_unknown test;
        // they cannot become restart state.
        assert_eq!(next.changed(&boot), ["/listen"]);
        assert!(boot.changed(&boot).is_empty());
        // Rebuilding another generation cannot reset the immutable boot comparison.
        assert_eq!(next.clone().changed(&boot), next.changed(&boot));
        // A fresh process binds the new configuration as its baseline.
        assert!(next.changed(&next).is_empty());
    }

    #[test]
    fn changed_tls_reference_is_detected_even_when_readback_presence_is_unchanged() {
        let sources = crate::config::secret::fixture_sources();
        let tls = TlsCfg {
            cert: super::super::SecretRef::template("CERT_A", &sources).unwrap(),
            key: super::super::SecretRef::template("KEY_A", &sources).unwrap(),
            client_ca: None,
        };
        let mut boot = baseline();
        boot.tls = Some(tls.clone());
        let mut next = boot.clone();
        next.tls = Some(TlsCfg {
            cert: super::super::SecretRef::template("CERT_B", &sources).unwrap(),
            ..tls
        });
        assert_eq!(next.changed(&boot), ["/tls"]);
    }

    #[test]
    fn connector_protocol_changes_use_authored_advanced_paths() {
        let boot = baseline();
        let mut next = boot.clone();
        next.limits.upstream_http1_only = !boot.limits.upstream_http1_only;
        next.limits.upstream_h2_prior_knowledge = !boot.limits.upstream_h2_prior_knowledge;
        assert_eq!(
            next.changed(&boot),
            [
                "/advanced/upstream_http1_only",
                "/advanced/upstream_h2_prior_knowledge"
            ]
        );
        let mut live = boot.clone();
        live.limits.request_body_max_bytes += 1;
        assert!(live.changed(&boot).is_empty());
    }

    #[test]
    fn source_only_workers_headers_and_mtls_changes_are_not_lost_by_resolution() {
        let mut deploy: DeployCfg = busbar_contract::yaml::from_str("{}").unwrap();
        let boot = Source::capture(&deploy);
        deploy.advanced.worker_threads = Some(3);
        deploy.advanced.response_headers.server_timing =
            !deploy.advanced.response_headers.server_timing;
        deploy.admin_require_mtls = !deploy.admin_require_mtls;
        let next = Source::capture(&deploy);
        assert_eq!(
            next.changed(&boot),
            [
                "/advanced/worker_threads",
                "/advanced/response_headers",
                "/admin_require_mtls"
            ]
        );
        assert!(next.changed(&next).is_empty());
    }

    #[test]
    fn changing_only_a_secret_instance_module_requires_restart() {
        let mut boot = baseline();
        boot.secrets.insert(
            "credentials".into(),
            busbar_contract::yaml::from_str("module: source-a\nsettings: {key: unchanged}\n")
                .unwrap(),
        );
        let mut next = boot.clone();
        next.secrets.get_mut("credentials").unwrap().module = "source-b".into();
        assert_eq!(next.changed(&boot), ["/secrets"]);
        assert_eq!(next.clone().changed(&boot), ["/secrets"]);
        assert!(boot.changed(&boot).is_empty());
        assert!(next.changed(&next).is_empty());
    }

    #[test]
    fn opaque_store_and_secret_settings_compare_without_public_serialization() {
        let mut boot = baseline();
        boot.store = Some(
            busbar_contract::yaml::from_str("module: neutral\nsettings: {x: first}\n").unwrap(),
        );
        boot.secrets.insert(
            "secret".into(),
            busbar_contract::yaml::from_str("module: neutral-secret\nsettings: {x: first}\n")
                .unwrap(),
        );
        let mut next = boot.clone();
        next.store = Some(
            busbar_contract::yaml::from_str("module: neutral\nsettings: {x: second}\n").unwrap(),
        );
        next.secrets.insert(
            "secret".into(),
            busbar_contract::yaml::from_str("module: neutral-secret\nsettings: {x: second}\n")
                .unwrap(),
        );
        assert_eq!(next.changed(&boot), ["/store", "/secrets"]);
    }
}
