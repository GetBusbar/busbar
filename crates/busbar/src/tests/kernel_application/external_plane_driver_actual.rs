// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};
use std::time::Duration;

#[path = "../../root/tests/test_plugins.rs"]
mod actual_plugins;

// Only the real distribution mounts this suite. This is a component HookEnv proof;
// it does not claim a cold application boot or route admission proof.
fn actual_rewrite(
    on_error: &str,
) -> Vec<(Duration, Arc<dyn busbar_contract::hooks::RoutingPolicy>)> {
    crate::dist_root_install::install();
    static ENDPOINT: OnceLock<String> = OnceLock::new();
    let endpoint = ENDPOINT.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind actual hook HTTP peer");
        let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for connection in listener.incoming() {
                let mut connection = connection.expect("accept hook HTTP call");
                connection.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut byte = [0];
                    connection.read_exact(&mut byte).expect("read hook HTTP headers");
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") { break request.len(); }
                    assert!(request.len() < 65536, "bounded hook HTTP headers");
                };
                let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
                let count: usize = headers.lines().find_map(|line| line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse().unwrap())).unwrap_or(0);
                let mut body = vec![0; count];
                connection.read_exact(&mut body).expect("read hook HTTP body");
                let _: serde_json::Value = serde_json::from_slice(&body).expect("actual Webrequest sends JSON");
                let reply = br#"{"rewrite":{"messages":[{"role":"user","content":"rewritten"}]}}"#;
                write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
                connection.write_all(reply).expect("answer the actual hook");
            }
        });
        endpoint
    });
    let directory = actual_plugins::scratch(&format!(
        "plane-actual-rewrite-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let mut store_module = None;
    let mut hook_module = None;
    for (kind, variable) in [
        ("store", "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN"),
        ("hook", "BUSBAR_TEST_WEBREQUEST_CDYLIB"),
    ] {
        let path = std::path::PathBuf::from(
            std::env::var_os(variable)
                .unwrap_or_else(|| panic!("{variable} names the actual built product")),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
            .expect("read actual product statement")
            .expect("product exports its statement");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("valid actual statement");
        let mut manifest = actual_plugins::manifest(
            kind,
            &facts.name,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        if kind == "hook" {
            manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
            manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
            hook_module = Some(facts.name);
        } else {
            store_module = Some(facts.name);
        }
        let library = std::fs::read(path).expect("read actual product library");
        let archive =
            actual_plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join(format!("{kind}.tar.gz")), archive)
            .expect("stage signed actual product");
    }
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings JSON");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
        "store": {"module": store_module.unwrap(), "settings": settings},
        "hooks": {"rw": {"module": hook_module.unwrap(), "kind": "gate", "prompt": "rw", "user": "ro", "global": true,
            "on_error": on_error, "timeout_ms": 5000, "settings": {"url": endpoint}}}
    })).expect("actual rewrite deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("actual rewrite deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("actual Store and Webrequest compose");
    limits.keep().expect("component limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let chain = busbar_kernel::hooks::resolve_rewrite_hooks(
        &app.hook_registry,
        &["rw".into()],
        &app.hook_env,
        0,
    );
    assert_eq!(
        chain.len(),
        1,
        "actual signed rw gate resolves into rewrite chain"
    );
    chain
}

#[tokio::test]
async fn actual_webrequest_supplies_a_rewrite_to_the_host_policy() {
    use busbar_contract::hooks::{RoutingRequest, TransformOutcome};
    let policies = actual_rewrite("weighted");
    assert_eq!(policies.len(), 1);
    // The six raw plane-projection fault cases live beside the kernel's owning ABI tests.
    // This control crosses the actual signed Webrequest product independently.
    let request = RoutingRequest {
        request_id: 1,
        pool: "test",
        ingress_protocol: "test-dialect",
        requested_model: None,
        message_count: 0,
        tool_count: 0,
        has_tools: false,
        total_chars: 0,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: Default::default(),
        session: None,
    };
    let outcome = policies[0].1.transform(&request, policies[0].0).await;
    assert!(
        matches!(outcome, TransformOutcome::Rewrite(_)),
        "{outcome:?}"
    );
}
