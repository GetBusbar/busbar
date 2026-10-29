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

// The one connector is built from this build's linked transport doors; a build that links none
// (`--no-default-features`) has no connector to build, so this cell gates on the transport-door axis.
#[cfg(linked_axis_transport_door)]
#[test]
fn the_process_has_one_connector_and_every_path_takes_it() {
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

// ── THE METADATA CARVE-OUTS, AS A DEPLOYMENT WRITES THEM ──
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
            judge.judge_name(&format!("https://{IMDS}/"), class, false),
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
            judge.judge_name("http://metadata.google.internal/", class, false),
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
    let _registry = busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[
        busbar_kernel::test_support::neutral_fallback_plane(),
    ]);
    let boot = deployment(
        &[],
        "security:\n  allow_metadata_hosts: [169.254.169.254]\n\
         advanced:\n  allow_destinations: [\"127.0.0.1\", \"::1\"]\n",
    );
    let judge = dest_judge(&boot);
    // The boot path's own step: the root's rules hold the guard, and every build judged by them
    // raises its commit to it.
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> = Arc::new(
        crate::root::door_steps::Rules::hearing(judge.clone() as Arc<dyn DestJudge>),
    );
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        None,
        "the boot config carves it out"
    );
    busbar_kernel::test_support::build_once_under(deployment(&[], ""), None, &rules)
        .expect("the reload builds");
    assert_eq!(
        metadata_verdict(judge.as_ref(), "imds-proxy.test", EGRESS_PROVIDER),
        Some(DEST_METADATA),
        "the reload removed the carve-out"
    );
}

/// RED: a deployment
/// whose provider has no `advanced.allow_destinations` entry is refused the private address its
/// name answers with on a provider dial (its own configured host included); once the allowlist
/// names it, the same dial is admitted. Operator infrastructure reaches the private address with
/// no entry, and refuses metadata even with every carve-out.
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

/// RED against the pinned mint plugin before busbar-auth-oauth#43, whose mint needs were
/// operator infrastructure (security item 3; security.md:158/169: provider upstreams, "their
/// `base_url` and `token_url` included", are refused a private address unless allowlisted, which
/// BUSBAR-3025 warns of at `--validate`): every outbound need a linked auth plugin's Statement
/// declares, judged in the class the connector judges it in (`guard::judged_class`: a need whose
/// config names its target is lifted out of the default class only), is REFUSED a private address
/// by the strict guard, ADMITTED once `advanced.allow_destinations` names the host, and refused
/// cloud metadata. Its class keeps 1.5.5's plaintext to a private token endpoint (neither `open-web`
/// nor `loopback-allowed`, which refuse it). Read off every linked auth row's own Statement, never a
/// plugin's name. It rides EVERY linked auth row (`linked_every_auth`, build.rs), so the mint
/// plugin's needs are among them and the cell always proves one; a build missing an auth row does
/// not run it. Superseded: `every_linked_auth_plugins_outbound_needs_are_operator_infrastructure`.
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

/// RED: a plane's upstream need whose settings name a PROGRAM is dialled by
/// the one connector over a linked transport door that frames a program's pipes LINE BY LINE (the
/// line row's door, found by what it does, never by name): the connector spawns the program
/// (operator-infrastructure class; no shell, only its stated environment), its first line is one
/// frame with the newline stripped, a message written is one line to its stdin, and it is killed
/// on close.
// Every linked wire is composed: a build that leaves one unlinked is a different composition
// (`linked_every_transport`, emitted by build.rs).
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
        // The next frame on `conn`, read through the table.
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
            };
            let (owner, id) = (InstanceId(7), NeedId(n));
            // A door that frames over another layer carries no program: refused at declare.
            if c.declare_program(owner, id, &need, &program).is_err() {
                continue;
            }
            // A door that will not begin a framing over a program's pipes refuses the open.
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
