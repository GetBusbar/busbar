// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn judge() -> Arc<dyn busbar_kernel::host_services::DestJudge> {
    process::dest_judge(&Destinations::default()).expect("the default")
}

#[cfg(linked_axis_transport_door)]
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
    let doors = crate::LINKED_TRANSPORT_DOORS;
    assert!(!doors.is_empty(), "this build links a transport door");
    let built = process::build_with_secrets(
        || entries(doors, &TransportSettings::default()),
        judge(),
        &[],
        Arc::new(|_, _| {}),
        PoolPosture::NONE,
        busbar_core_connector::spawn_env::linked_spawn_secret,
    );
    let built = built.expect("the linked doors build a connector");
    let installed = install(Arc::clone(&built)).expect("the first install is the one");
    assert!(Arc::ptr_eq(installed, &built));
    assert!(Arc::ptr_eq(the(), &built), "the() is the installed one");
    let second = process::build_with_secrets(
        || entries(doors, &TransportSettings::default()),
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

use busbar_contract::abi::host::conn::connector::{
    EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    EGRESS_PROVIDER,
};
use busbar_contract::abi::host::service::DEST_METADATA;

const IMDS: &str = "169.254.169.254";

fn deployment(providers: &[(&str, &str, &[&str])], security: &str) -> RootCfg {
    let mut defs = std::collections::HashMap::new();
    let mut yaml = String::from("store: {module: memory}\nmodels: {}\nproviders:");
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

#[test]
fn a_reload_that_removes_a_carve_out_refuses_the_next_dial() {
    crate::dist_root_install::install();
    crate::root::test_plane_registry::register();
    let boot = deployment(
        &[],
        "security:\n  allow_metadata_hosts: [169.254.169.254]\n\
         advanced:\n  allow_destinations: [\"127.0.0.1\", \"::1\"]\n",
    );
    let judge = dest_judge(&boot);

    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> = Arc::new(
        crate::root::door_steps::Rules::hearing(judge.clone() as Arc<dyn DestJudge>),
    );
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        None,
        "the boot config carves it out"
    );
    let store = crate::root::real_store::store();
    let (_app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        deployment(&[], ""),
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(busbar_contract::store_calls::OpenedStore {
            records: store.clone(),
            calls: Some(store),
        }),
        false,
    )
    .expect("the reload builds");
    limits.keep().expect("the reload commits its limits");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        Some(DEST_METADATA),
        "the reload removed the carve-out"
    );
}

#[test]
fn a_reload_that_changes_the_allowlist_changes_nothing() {
    use busbar_contract::abi::host::service::DEST_INTERNAL;
    crate::dist_root_install::install();
    crate::root::test_plane_registry::register();
    let private_a = vec!["10.0.0.5".parse().unwrap()];
    let private_b = vec!["10.0.0.9".parse().unwrap()];
    let verdict = |judge: &dyn DestJudge, host: &str, answer: &[std::net::IpAddr]| {
        judge
            .judge_answer(host, answer, EGRESS_PROVIDER)
            .err()
            .map(|r| r.verdict)
    };

    let boot = deployment(&[], "advanced:\n  allow_destinations: [model-a.internal]\n");
    let judge = dest_judge(&boot);
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> = Arc::new(
        crate::root::door_steps::Rules::hearing(judge.clone() as Arc<dyn DestJudge>),
    );
    assert_eq!(
        verdict(judge.as_ref(), "model-a.internal", &private_a),
        None
    );
    assert_eq!(
        verdict(judge.as_ref(), "model-b.internal", &private_b),
        Some(DEST_INTERNAL),
        "the host the boot did not name is refused"
    );
    let reloaded = deployment(&[], "advanced:\n  allow_destinations: [model-b.internal]\n");
    let store = crate::root::real_store::store();
    let (_app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        reloaded,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(busbar_contract::store_calls::OpenedStore {
            records: store.clone(),
            calls: Some(store),
        }),
        false,
    )
    .expect("the reload builds");
    limits.keep().expect("the reload commits its limits");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert_eq!(
        verdict(judge.as_ref(), "model-a.internal", &private_a),
        None,
        "the entry the reload removed still admits: the allowlist is read at boot"
    );
    assert_eq!(
        verdict(judge.as_ref(), "model-b.internal", &private_b),
        Some(DEST_INTERNAL),
        "the entry the reload added admits nothing until a restart"
    );
}

#[test]
fn a_provider_without_an_allowlist_entry_is_refused_a_private_address() {
    use busbar_contract::abi::host::service::DEST_INTERNAL;
    let private = vec!["10.0.0.5".parse().unwrap()];
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
    let listed = deployment(
        &[("local_model", "http://model.internal:8000", &[IMDS])],
        "advanced:\n  allow_destinations: [model.internal]\n",
    );
    let judge = guard_for(&listed.destinations()).expect("a guard");
    assert_eq!(
        judge.judge_answer("model.internal", &private, EGRESS_PROVIDER),
        Ok(()),
        "the allowlist admits it"
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

#[cfg(linked_every_auth)]
#[test]
fn every_linked_auth_plugins_outbound_need_is_refused_a_private_address_unless_allowlisted() {
    use busbar_contract::abi::host::service::DEST_INTERNAL;
    let private = vec!["10.0.0.5".parse().unwrap()];
    let strict = guard_for(&deployment(&[], "").destinations()).expect("the default guard");
    let listed = deployment(&[], "advanced:\n  allow_destinations: [token.internal]\n");
    let listed = guard_for(&listed.destinations()).expect("a guard");
    let mut outbound = 0usize;
    for &(key, _, door) in crate::LINKED.auths {
        let row = crate::root::loader::dispatch::LinkedRow::of(door)
            .unwrap_or_else(|e| panic!("`{key}`'s door states itself: {e}"));
        let read = busbar_contract::abi::mechanism::rendering::read(&row.statement)
            .unwrap_or_else(|e| panic!("`{key}`'s Statement reads: {e:?}"));
        for (n, need) in read.needs.iter().enumerate() {
            if need.direction != busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND {
                continue;
            }
            outbound += 1;
            let class = busbar_core_connector::guard::judged_class(
                need.egress_class,
                !need.target_from.is_empty(),
            );
            assert_eq!(
                strict
                    .judge_answer("token.internal", &private, class)
                    .err()
                    .map(|r| r.verdict),
                Some(DEST_INTERNAL),
                "`{key}`'s outbound need {n} (class {}, judged {class}) must refuse a private \
                 token endpoint with no allow entry",
                need.egress_class
            );
            assert_eq!(
                listed.judge_answer("token.internal", &private, class),
                Ok(()),
                "`{key}`'s outbound need {n}: an allow entry admits it"
            );
            assert_eq!(
                metadata_verdict(strict.as_ref(), "token.internal", class),
                Some(DEST_METADATA),
                "`{key}`'s outbound need {n}: metadata is refused"
            );
            assert!(
                ![EGRESS_OPEN_WEB, EGRESS_LOOPBACK_ALLOWED].contains(&need.egress_class),
                "`{key}`'s outbound need {n}: 1.5.5 minted over plaintext to a private token \
                 endpoint, which open-web and loopback-allowed refuse"
            );
        }
    }
    assert!(
        outbound > 0,
        "the linked auth rows declare an outbound need (the mint needs), so this cell proves one"
    );
}

#[cfg(linked_every_transport)]
#[test]
fn a_program_need_is_dialled_through_the_linked_line_framing_door() {
    use busbar_contract::abi::host::conn::connector::{
        DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
    };
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_contract::conn::{
        ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc,
    };
    let doors = crate::LINKED_TRANSPORT_DOORS;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        let c = process::build_with_secrets(
            || entries(doors, &TransportSettings::default()),
            judge(),
            &[],
            Arc::new(|_, _| {}),
            PoolPosture::NONE,
            busbar_core_connector::spawn_env::linked_spawn_secret,
        )
        .expect("the linked doors build a connector");
        let program = busbar_contract::conn::Program::from_settings(&serde_json::json!({
            "command": "/bin/sh",
            "args": ["-c", "echo \"got:$DECLARED\"; read line; echo \"again:$line\""],
            (busbar_contract::conn::PROGRAM_ENV_KEY): {"DECLARED": "yes"},
        }))
        .expect("a program");

        let frame = |conn: ConnId| {
            let c = &c;
            async move {
                let mut buf = [0_u8; 128];
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                loop {
                    match c.read(InstanceId(7), conn, 1, &mut buf) {
                        Ok(piece) => break Some(buf[..piece.len].to_vec()),
                        Err(ConnError::Pending) if std::time::Instant::now() < deadline => {
                            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        }
                        _ => break None,
                    }
                }
            }
        };
        let mut line_framed = Vec::new();
        for (n, (key, _)) in (0u32..).zip(doors.iter()) {
            let need = ReadNeed {
                direction: DIRECTION_OUTBOUND,
                egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
                transport: (*key).to_owned(),
                auth: String::new(),
                target_from: "settings.server".to_owned(),
                trust_from: String::new(),
                details: ReadBlob {
                    fmt: 0,
                    flags: 0,
                    bytes: Vec::new(),
                },
                timeout_ms: 0,
                keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
                keep_response_headers: Vec::new(),
                deny_response_headers: Vec::new(),
            };
            let (owner, id) = (InstanceId(7), NeedId(n));

            if c.declare_program(owner, id, &need, &program).is_err() {
                continue;
            }

            let Ok(conn) = c.open(owner, id, &OpenDesc::default()) else {
                continue;
            };
            if frame(conn).await.as_deref() == Some(b"got:yes".as_slice()) {
                assert_eq!(c.write(owner, conn, b"{\"id\":1}", true, false), Ok(8));
                assert_eq!(
                    frame(conn).await.as_deref(),
                    Some(b"again:{\"id\":1}".as_slice()),
                    "a message is one line to the program; its answer one frame back"
                );
                line_framed.push(*key);
            }
            c.close(owner, conn).expect("closes");
        }
        assert_eq!(
            line_framed.len(),
            1,
            "exactly one linked door frames a program line by line"
        );
    });
}
