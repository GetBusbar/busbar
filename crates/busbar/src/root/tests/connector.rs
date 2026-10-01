// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE CONNECTOR: built from this build's linked transport doors, installed once, and the same
//! instance whoever asks for it; a second install is refused. The egress path takes its connection
//! table from this instance (`root::plane_egress::conns`), never from a connector of its own.

use super::*;

/// The strict default guard, as a deployment that states nothing builds it.
fn judge() -> Arc<dyn busbar_kernel::host_services::DestJudge> {
    process::dest_judge(&busbar_kernel::config::Destinations::default()).expect("the default")
}

#[test]
fn the_process_has_one_connector_and_every_path_takes_it() {
    let doors = crate::LINKED_TRANSPORT_DOORS;
    assert!(!doors.is_empty(), "this build links a transport door");
    let built = process::build(|| entries(doors), judge(), &[], Arc::new(|_| {}));
    let built = built.expect("the linked doors build a connector");
    let installed = install(Arc::clone(&built)).expect("the first install is the one");
    assert!(Arc::ptr_eq(installed, &built));
    assert!(Arc::ptr_eq(the(), &built), "the() is the installed one");
    let egress = crate::root::plane_egress::conns();
    let same: Arc<dyn busbar_contract::conn::PollConns> = Arc::clone(&built) as _;
    assert!(
        std::ptr::addr_eq(Arc::as_ptr(&egress), Arc::as_ptr(&same)),
        "the egress path's connection table is the one connector"
    );
    let second = process::build(|| entries(doors), judge(), &[], Arc::new(|_| {}))
        .expect("a second one builds");
    assert!(install(second).is_err(), "a second connector is refused");
    assert!(Arc::ptr_eq(the(), &built));
}

/// A resolved deployment with one provider at `base_url`, allowing `allow`.
fn provider_at(base_url: &str, allow: &[&str]) -> busbar_kernel::config::RootCfg {
    let deploy = busbar_kernel::config::deploy_from_yaml_str("providers: {}\nmodels: {}\n")
        .expect("a minimal deployment");
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
    cfg.allow_destinations = allow.iter().map(|s| (*s).to_owned()).collect();
    cfg.providers.insert(
        "local".into(),
        busbar_kernel::config::ProviderCfg {
            protocol: "openai".into(),
            base_url: base_url.into(),
            api_key: busbar_kernel::config::SecretRef::env("LOCAL_KEY"),
            health: None,
            error_map: Default::default(),
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            subject: None,
            auth: None,
            allow_metadata_hosts: Vec::new(),
            max_output_key: None,
            anthropic_adaptive_thinking: None,
            native_structured_output: None,
            model_capabilities: Vec::new(),
        },
    );
    cfg
}

fn preflight_of(cfg: &busbar_kernel::config::RootCfg) -> Vec<String> {
    let dest = process::dest_judge(&cfg.destinations()).expect("the guard");
    preflight(cfg, dest.guard())
}

/// RED (the destination guard at boot and `--validate`): a provider on a private literal or a
/// `localhost` name is refused by default, by the one guard's name arm, naming the provider and
/// the key; a public host is not.
#[test]
fn a_provider_on_a_private_literal_is_refused_at_validate() {
    assert_eq!(
        preflight_of(&provider_at("http://127.0.0.1:11434/v1", &[])),
        [
            "provider 'local' base_url: host `127.0.0.1` resolves to the internal address \
          127.0.0.1; list it in advanced.allow_destinations to allow it"
        ]
    );
    assert_eq!(
        preflight_of(&provider_at("http://localhost:11434", &[])).len(),
        1
    );
    assert!(preflight_of(&provider_at("https://api.example.com", &[])).is_empty());
}

/// GREEN: the same provider validates once the allowlist names it.
#[test]
fn a_provider_on_a_private_literal_validates_when_allowlisted() {
    assert!(preflight_of(&provider_at("http://127.0.0.1:11434/v1", &["127.0.0.1"])).is_empty());
    assert!(preflight_of(&provider_at("http://localhost:11434", &["localhost"])).is_empty());
}
