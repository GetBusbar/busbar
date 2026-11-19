// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn judge() -> Arc<dyn busbar_kernel::host_services::DestJudge> {
    process::dest_judge(&Destinations::default()).expect("the default")
}

#[test]
fn the_process_has_one_connector_and_every_path_takes_it() {
    const CHILD: &str = "BUSBAR_TEST_CONNECTOR_SINGLETON_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "root::connector::tests::the_process_has_one_connector_and_every_path_takes_it",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("the isolated connector test starts");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 passed; 0 failed"),
            "the isolated singleton test must run and pass: {}\n{stdout}\n{stderr}",
            output.status
        );
        return;
    }
    let built = process::build_with_secrets(
        || Ok(Vec::new()),
        judge(),
        &[],
        Arc::new(|_, _| {}),
        PoolPosture::NONE,
        busbar_core_connector::spawn_env::linked_spawn_secret,
    );
    let built = built.expect("the process connector builds");
    let installed = install(Arc::clone(&built)).expect("the first install is the one");
    assert!(Arc::ptr_eq(installed, &built));
    assert!(Arc::ptr_eq(the(), &built), "the() is the installed one");
    let second = process::build_with_secrets(
        || Ok(Vec::new()),
        judge(),
        &[],
        Arc::new(|_, _| {}),
        PoolPosture::NONE,
        busbar_core_connector::spawn_env::linked_spawn_secret,
    )
    .expect("a second one builds");
    assert!(install(second).is_err(), "a second connector is refused");
    assert!(Arc::ptr_eq(the(), &built));
}

use busbar_contract::conn::codes::{
    EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    EGRESS_PROVIDER,
};
use busbar_contract::services::codes::DEST_METADATA;

const IMDS: &str = "169.254.169.254";

fn deployment(providers: &[(&str, &str, &[&str])], security: &str) -> RootCfg {
    crate::root::linked::register_stores();
    let mut defs = std::collections::HashMap::new();
    let mut yaml = String::from("store: {module: memory}\nmodels: {}\nproviders:");
    yaml.push_str(if providers.is_empty() { " {}\n" } else { "\n" });
    for (name, url, carve) in providers {
        let def: busbar_kernel::config::ProviderDef =
            busbar_contract::yaml::from_str(&format!("protocol: openai\nbase_url: {url}\n"))
                .expect("a def");
        defs.insert((*name).to_owned(), def);
        let carve = carve.join(", ");
        yaml.push_str(&format!(
            "  {name}:\n    api_key: {{ env: BUSBAR_TEST_KEY }}\n    allow_metadata_hosts: [{carve}]\n"
        ));
    }
    yaml.push_str(security);
    let deploy =
        busbar_kernel::config::deploy_from_yaml_str(&yaml, &crate::root::boot::axis_test_grammar())
            .expect("parses");
    busbar_kernel::config::resolve(&deploy, &defs).expect("resolves")
}

fn imds() -> Vec<std::net::IpAddr> {
    vec![IMDS.parse().unwrap()]
}

fn metadata_verdict(judge: &dyn DestJudge, host: &str, class: u32) -> Option<u64> {
    judge
        .judge_answer(host, &imds(), class)
        .err()
        .map(|r| r.verdict)
}

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
            judge.judge_name(&format!("https://{IMDS}/"), class, false),
            Err(DEST_METADATA),
            "the literal under class {class}"
        );
    }
}

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
        Some(DEST_METADATA),
        "even the provider's own host cannot carve out metadata"
    );
    for host in ["other-provider.test", "unnamed.test"] {
        assert_eq!(
            metadata_verdict(judge.as_ref(), host, EGRESS_PROVIDER),
            Some(DEST_METADATA),
            "`{host}`"
        );
    }
}

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
            judge.judge_name("http://metadata.google.internal/", class, false),
            Err(DEST_METADATA),
            "the metadata name under class {class}"
        );
    }
}

#[tokio::test]
async fn metadata_stays_refused_across_reload() {
    crate::dist_root_install::install();
    let boot = deployment(
        &[],
        "security:\n  blocked_metadata_hosts: [169.254.169.254]\n",
    );
    let judge = dest_judge(&boot);

    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> = Arc::new(
        crate::root::door_steps::Rules::hearing(judge.clone() as Arc<dyn DestJudge>),
    );
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        Some(DEST_METADATA),
        "the boot configuration cannot admit metadata"
    );
    let store = crate::root::real_store::core().await;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        deployment(&[], ""),
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(store.clone()),
        false,
    )
    .await
    .expect("the reload builds");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD
        .keep_in_store(
            app.governance
                .as_ref()
                .expect("the actual deployment configured governance")
                .core_store_handle()
                .expect("the actual configured Store exposes its rate-history slots"),
            122,
        )
        .expect("native rate history attaches");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the actual configured Store boots its rate history");
    limits.keep().await.expect("the reload commits its limits");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        Some(DEST_METADATA),
        "the reload removed the carve-out"
    );
}

#[tokio::test]
async fn provider_configuration_never_grants_global_hostname_authority_across_reload() {
    use busbar_contract::services::codes::DEST_INTERNAL;
    crate::dist_root_install::install();
    let private_a = vec!["\x310.0.0.5".parse().unwrap()];
    let private_b = vec!["\x310.0.0.9".parse().unwrap()];
    let verdict = |judge: &dyn DestJudge, host: &str, answer: &[std::net::IpAddr]| {
        judge
            .judge_answer(host, answer, EGRESS_PROVIDER)
            .err()
            .map(|r| r.verdict)
    };

    let boot = deployment(&[("a", "https://model-a.internal", &[])], "");
    let judge = dest_judge(&boot);
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> = Arc::new(
        crate::root::door_steps::Rules::hearing(judge.clone() as Arc<dyn DestJudge>),
    );
    assert_eq!(
        verdict(judge.as_ref(), "model-a.internal", &private_a),
        Some(DEST_INTERNAL)
    );
    assert_eq!(
        verdict(judge.as_ref(), "model-b.internal", &private_b),
        Some(DEST_INTERNAL),
        "the host the boot did not name is refused"
    );
    let reloaded = deployment(&[("b", "https://model-b.internal", &[])], "");
    let store = crate::root::real_store::core().await;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(reloaded),
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(store.clone()),
        false,
    )
    .await
    .expect("the reload builds");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD
        .keep_in_store(
            app.governance
                .as_ref()
                .expect("the actual deployment configured governance")
                .core_store_handle()
                .expect("the actual configured Store exposes its rate-history slots"),
            122,
        )
        .expect("native rate history attaches");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the actual configured Store boots its rate history");
    limits.keep().await.expect("the reload commits its limits");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    assert_eq!(
        verdict(judge.as_ref(), "model-a.internal", &private_a),
        Some(DEST_INTERNAL),
        "a prior provider route never gives arbitrary requests global reach"
    );
    assert_eq!(
        verdict(judge.as_ref(), "model-b.internal", &private_b),
        Some(DEST_INTERNAL),
        "the new provider route gives arbitrary same-host requests no reach"
    );
}

#[test]
fn a_provider_host_grants_no_authority_to_generic_destination_judging() {
    use busbar_contract::services::codes::DEST_INTERNAL;
    let private = vec!["\x310.0.0.5".parse().unwrap()];
    let bare = deployment(&[("local_model", "http://model.internal:8000", &[])], "");
    let judge = guard_for(&bare.destinations()).expect("a guard");
    assert_eq!(
        judge
            .judge_answer("model.internal", &private, EGRESS_PROVIDER)
            .err()
            .map(|r| r.verdict),
        Some(DEST_INTERNAL),
        "the provider's own host, no allowlist entry"
    );
    assert_eq!(
        judge.judge_answer("model.internal", &private, EGRESS_OPERATOR_INFRASTRUCTURE),
        Ok(()),
        "operator infrastructure needs no entry"
    );
    let listed = deployment(&[("local_model", "http://model.internal:8000", &[])], "");
    let judge = guard_for(&listed.destinations()).expect("a guard");
    assert_eq!(
        judge
            .judge_answer("model.internal", &private, EGRESS_PROVIDER)
            .unwrap_err()
            .verdict,
        DEST_INTERNAL,
        "a configured provider host gives generic judging no reach"
    );
    assert_eq!(
        metadata_verdict(
            judge.as_ref(),
            "model.internal",
            EGRESS_OPERATOR_INFRASTRUCTURE
        ),
        Some(DEST_METADATA),
        "operator infrastructure refuses metadata whatever is carved"
    );
}
