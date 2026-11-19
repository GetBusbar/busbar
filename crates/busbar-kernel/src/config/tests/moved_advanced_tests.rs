// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Operator settings that move out of `advanced` to the section they belong to. An old
//! configuration is converted, never refused: the old key is read, its value lands at the new
//! home (unless the new home is also written, which wins), one line says so, the old key is never
//! written back, and the resolved configuration is the same as if the new key had been written.

use std::collections::HashMap;

use super::tests::base_deploy;
use super::*;

/// Read `text` as boot reads it and resolve it on the test base, keeping its moved sections.
fn read(text: &str) -> (DeployCfg, RootCfg) {
    let parsed = deploy_from_yaml_str(text, &Grammar::empty())
        .unwrap_or_else(|e| panic!("an old configuration must load: {e:?}\n{text}"));
    let mut deploy = base_deploy();
    deploy.advanced = parsed.advanced;
    deploy.shutdown = parsed.shutdown;
    deploy.client_address = parsed.client_address;
    deploy.outbound = parsed.outbound;
    deploy.telemetry = parsed.telemetry;
    deploy.carried = parsed.carried;
    let cfg = resolve(&deploy, &HashMap::new())
        .unwrap_or_else(|e| panic!("an old configuration must resolve: {e:?}\n{text}"));
    (deploy, cfg)
}

/// The old document and the new one resolve the same, the old key is never written back, and
/// one line names the old key and its new home.
fn moves(old: &str, new: &str, old_key: &str, new_key: &str) -> (DeployCfg, RootCfg) {
    let (old_deploy, old_cfg) = read(old);
    let (_, new_cfg) = read(new);
    assert_eq!(
        format!("{:?}", old_deploy.carried),
        format!(
            "{:?}",
            [format!(
                "advanced.{old_key} moved to {new_key}; the value was carried over"
            )]
        ),
        "one line for {old_key}"
    );
    let written = busbar_contract::yaml::to_string(&old_deploy.advanced).expect("serializes");
    let leaf = old_key.rsplit('.').next().expect("a key");
    assert!(
        !written.contains(leaf),
        "{old_key} is not written back: {written}"
    );
    assert_eq!(
        format!("{:?}", old_cfg.limits),
        format!("{:?}", new_cfg.limits)
    );
    (old_deploy, old_cfg)
}

#[test]
fn advanced_shutdown_deregister_delay_moves_to_shutdown() {
    let (deploy, _) = moves(
        "advanced:\n  shutdown:\n    deregister_delay: 7s\n",
        "shutdown:\n  deregister_delay: 7s\n",
        "shutdown.deregister_delay",
        "shutdown.deregister_delay",
    );
    assert_eq!(deploy.shutdown.delay(), std::time::Duration::from_secs(7));
}

#[test]
fn the_deregister_delay_defaults_to_none_and_a_written_one_wins() {
    let (deploy, _) = read("{}\n");
    assert_eq!(deploy.shutdown.delay(), std::time::Duration::ZERO);
    let (deploy, _) = read(
        "shutdown:\n  deregister_delay: 3s\nadvanced:\n  shutdown:\n    deregister_delay: 9s\n",
    );
    assert_eq!(deploy.shutdown.delay(), std::time::Duration::from_secs(3));
    assert_eq!(deploy.carried.len(), 1, "{:?}", deploy.carried);
    assert!(deploy.carried[0].contains("wins"), "{:?}", deploy.carried);
}

#[test]
fn trusted_proxies_and_forwarded_header_move_to_client_address() {
    let (deploy, cfg) =
        read("advanced:\n  trusted_proxies: [10.0.0.0/8]\n  forwarded_header: forwarded\n");
    let (_, new_cfg) =
        read("client_address:\n  trusted_proxies: [10.0.0.0/8]\n  header: forwarded\n");
    assert_eq!(deploy.client_address.trusted_proxies, ["10.0.0.0/8"]);
    assert_eq!(deploy.client_address.header.as_deref(), Some("forwarded"));
    assert_eq!(
        format!("{:?}", cfg.login_limits.proxies),
        format!("{:?}", new_cfg.login_limits.proxies)
    );
    assert_eq!(deploy.carried.len(), 2, "{:?}", deploy.carried);
    let written = busbar_contract::yaml::to_string(&deploy.advanced).expect("serializes");
    assert!(!written.contains("trusted_proxies"), "{written}");
    assert!(!written.contains("forwarded_header"), "{written}");
}

#[test]
fn the_outbound_keys_move_to_outbound() {
    let (deploy, cfg) = read(
        "advanced:\n  block_private_addresses: false\n  proxy_resolution: proxy\n  \
         upstream_http1_only: true\n  upstream_h2_prior_knowledge: true\n  tls:\n    roots: system\n",
    );
    let (_, new_cfg) = read(
        "outbound:\n  block_private_addresses: false\n  proxy_resolution: proxy\n  \
         http1_only: true\n  h2_prior_knowledge: true\n  tls:\n    roots: system\n",
    );
    assert!(!deploy.outbound.block_private_addresses);
    assert!(deploy.outbound.http1_only && deploy.outbound.h2_prior_knowledge);
    assert_eq!(deploy.outbound.tls.roots, tls::TlsRoots::System);
    assert_eq!(
        deploy.outbound.proxy_resolution,
        tls::ProxyResolution::Proxy
    );
    assert_eq!(cfg.destinations(), new_cfg.destinations());
    assert_eq!(cfg.outbound_tls, new_cfg.outbound_tls);
    assert_eq!(cfg.proxy_resolution, new_cfg.proxy_resolution);
    assert!(cfg.limits.upstream_http1_only && cfg.limits.upstream_h2_prior_knowledge);
    assert_eq!(deploy.carried.len(), 5, "{:?}", deploy.carried);
    let written = busbar_contract::yaml::to_string(&deploy.advanced).expect("serializes");
    for key in [
        "block_private_addresses",
        "proxy_resolution",
        "upstream_http1_only",
        "upstream_h2_prior_knowledge",
        "tls",
    ] {
        assert!(!written.contains(key), "{key}: {written}");
    }
}

#[test]
fn private_addresses_stay_blocked_by_default_at_the_new_home() {
    let (deploy, cfg) = read("{}\n");
    assert!(deploy.outbound.block_private_addresses);
    assert!(cfg.destinations().block_private_addresses);
}

#[test]
fn server_timing_moves_to_telemetry() {
    moves(
        "advanced:\n  response_headers:\n    server_timing: true\n",
        "telemetry:\n  response_headers:\n    server_timing: true\n",
        "response_headers.server_timing",
        "telemetry.response_headers.server_timing",
    );
    let (deploy, _) = read("advanced:\n  response_headers:\n    server_timing: true\n");
    assert!(deploy.telemetry.response_headers.server_timing);
}

/// A document edit (the admin configuration document) at an old path applies at the new home.
#[test]
fn a_document_edit_at_an_old_path_lands_at_the_new_home() {
    let edit = crate::config::document_patch::DocumentPatch::from_value(serde_json::json!({
        "set": {"/advanced/trusted_proxies": ["192.0.2.0/24"], "/advanced/tls/roots": "system"}
    }))
    .expect("patch");
    let edited = edit
        .parse_deploy_yaml("providers: {}\nmodels: {}\n")
        .expect("the edit applies");
    assert_eq!(edited.client_address.trusted_proxies, ["192.0.2.0/24"]);
    assert_eq!(edited.outbound.tls.roots, tls::TlsRoots::System);
}
