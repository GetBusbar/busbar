// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE CONNECTOR: built from this build's linked transport doors, installed once, and the same
//! instance whoever asks for it; a second install is refused. Every path that dials or declares
//! takes this instance (`root::connector::the()`), never a connector of its own.

use super::*;

/// The strict default guard, as a deployment that states nothing builds it.
fn judge() -> Arc<dyn busbar_kernel::host_services::DestJudge> {
    process::dest_judge(&Destinations::default()).expect("the default")
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
    let second = process::build(|| entries(doors), judge(), &[], Arc::new(|_| {}))
        .expect("a second one builds");
    assert!(install(second).is_err(), "a second connector is refused");
    assert!(Arc::ptr_eq(the(), &built));
}

/// A bad `advanced.allow_destinations` entry refuses the guard's build (the boot and `--validate`
/// refusal), naming the key and the entry.
#[test]
fn a_bad_allowlist_entry_refuses_the_guard() {
    let d = Destinations {
        allow: vec!["host.test:8080".into()],
        ..Destinations::default()
    };
    let refusal = process::dest_judge(&d).err().expect("refused");
    assert!(
        refusal.starts_with("advanced.allow_destinations[0]: `host.test:8080`"),
        "{refusal}"
    );
}

// ── THE METADATA CARVE-OUTS, AS A DEPLOYMENT WRITES THEM (ARCHITECT ruling on #413, DEST-GUARD) ──
// A provider's `allow_metadata_hosts` admits a metadata address only in the provider class and only
// for that provider's own URL host; no other class admits metadata through any carve-out (the 1.5.5
// `security` keys included), and operator infrastructure refuses it whatever the carve-outs say.
// The lists are re-read at every config commit, as 1.5.5 and train/1 re-read them.

use busbar_contract::abi::host::conn::connector::{
    EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    EGRESS_PROVIDER,
};
use busbar_contract::abi::host::service::DEST_METADATA;

/// The AWS/GCP/Azure IMDS address every carve-out below names.
const IMDS: &str = "169.254.169.254";

/// A resolved deployment: `providers` as `(name, base_url, allow_metadata_hosts)`, every one in
/// the catalog, and `security` (YAML, or empty for none).
fn deployment(providers: &[(&str, &str, &[&str])], security: &str) -> RootCfg {
    let mut defs = std::collections::HashMap::new();
    let mut yaml = String::from("models: {}\nproviders:");
    yaml.push_str(if providers.is_empty() { " {}\n" } else { "\n" });
    for (name, url, carve) in providers {
        let def: busbar_kernel::config::ProviderDef =
            serde_yaml::from_str(&format!("protocol: openai\nbase_url: {url}\n")).expect("a def");
        defs.insert((*name).to_owned(), def);
        let carve = carve.join(", ");
        yaml.push_str(&format!(
            "  {name}:\n    api_key: {{ env: BUSBAR_TEST_KEY }}\n    allow_metadata_hosts: [{carve}]\n"
        ));
    }
    yaml.push_str(security);
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parses");
    busbar_kernel::config::resolve(&deploy, &defs).expect("resolves")
}

fn imds() -> Vec<std::net::IpAddr> {
    vec![IMDS.parse().unwrap()]
}

/// The verdict `judge` answers for `host` answering the IMDS address under `class`.
fn metadata_verdict(judge: &dyn DestJudge, host: &str, class: u32) -> Option<u64> {
    judge
        .judge_answer(host, &imds(), class)
        .err()
        .map(|r| r.verdict)
}

/// RED: a provider's carve-out does not admit the metadata address for a default-class or
/// open-web dial, its own host included; nor does the global 1.5.5 carve-out.
#[test]
fn a_provider_carve_out_does_not_admit_metadata_for_a_default_or_open_web_dial() {
    let cfg = deployment(
        &[("imds_proxy", "https://imds-proxy.test", &[IMDS])],
        "security:\n  allow_metadata_hosts: [169.254.169.254]\n",
    );
    let judge = guard_for(&cfg.destinations()).expect("a guard");
    for class in [EGRESS_DEFAULT, EGRESS_OPEN_WEB] {
        for host in ["open.example", "imds-proxy.test"] {
            assert_eq!(
                metadata_verdict(judge.as_ref(), host, class),
                Some(DEST_METADATA),
                "`{host}` under class {class}"
            );
        }
        assert_eq!(
            judge.judge_name(&format!("https://{IMDS}/"), class),
            Err(DEST_METADATA),
            "the literal under class {class}"
        );
    }
}

/// RED: a provider's carve-out admits the metadata address for that provider's own URL host, in
/// the provider class, and for no other provider's host.
#[test]
fn a_provider_carve_out_does_not_admit_metadata_for_another_provider_host() {
    let cfg = deployment(
        &[
            ("imds_proxy", "https://imds-proxy.test/v1", &[IMDS]),
            ("other", "https://other-provider.test", &[]),
        ],
        "",
    );
    let judge = guard_for(&cfg.destinations()).expect("a guard");
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        None,
        "the carving provider's own host"
    );
    for host in ["other-provider.test", "unnamed.test"] {
        assert_eq!(
            metadata_verdict(judge.as_ref(), host, EGRESS_PROVIDER),
            Some(DEST_METADATA),
            "`{host}`"
        );
    }
}

/// RED: operator infrastructure (and loopback-allowed) refuse metadata even when every 1.5.5 key
/// carves it out: a provider's carve-out, the global carve-out and `allow_all_metadata`.
#[test]
fn operator_infrastructure_refuses_metadata_even_when_carved_out() {
    let cfg = deployment(
        &[("imds_proxy", "https://imds-proxy.test", &[IMDS])],
        "security:\n  allow_metadata_hosts: [169.254.169.254, metadata.google.internal]\n  \
         allow_all_metadata: true\n",
    );
    let judge = guard_for(&cfg.destinations()).expect("a guard");
    for class in [EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_LOOPBACK_ALLOWED] {
        for host in ["vault.internal", "imds-proxy.test"] {
            assert_eq!(
                metadata_verdict(judge.as_ref(), host, class),
                Some(DEST_METADATA),
                "`{host}` under class {class}"
            );
        }
        assert_eq!(
            judge.judge_name("http://metadata.google.internal/", class),
            Err(DEST_METADATA),
            "the metadata name under class {class}"
        );
    }
}

/// RED: the metadata lists are re-read at every config commit: the process's guard admits a
/// carve-out the boot config states, and once a reload that removes it commits, the next dial is
/// refused.
#[test]
fn a_reload_that_removes_a_carve_out_refuses_the_next_dial() {
    // Every app build reads the plane registry, so holding it isolated keeps every other test's
    // commit out of this one's window.
    let _registry = busbar_kernel::plane::registry::TestRegistryIsolation::seeded(&[
        busbar_kernel::test_support::neutral_fallback_plane(),
    ]);
    let boot = deployment(
        &[],
        "security:\n  allow_metadata_hosts: [169.254.169.254]\n",
    );
    let judge = dest_judge(&boot);
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        None,
        "the boot config carves it out"
    );
    busbar_kernel::test_support::build_once(deployment(&[], ""), None).expect("the reload builds");
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        Some(DEST_METADATA),
        "the reload removed the carve-out"
    );
}
