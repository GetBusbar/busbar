// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode};
use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_FILE};

use crate::root::door_steps::tests::tool_door::{
    send_headed, surface, three_tools, tool_digest, try_rig_tools, Rig, TlsToolServer, CALL,
};
use crate::root::serve::planes_tests::PUBLISHING;

const SOURCE_WORDS: [&str; 3] = ["environment variable", "is unset", "no such file"];

fn rendered(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> String {
    let mut out = format!(
        "{} {}\n",
        status.as_str(),
        status.canonical_reason().unwrap_or_default()
    );
    for (name, value) in headers {
        out.push_str(&format!(
            "{}: {}\n",
            name.as_str(),
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    out.push('\n');
    out.push_str(&String::from_utf8_lossy(body));
    out
}

fn source_in(render: &str, secret: &SecretRef) -> Vec<String> {
    let lower = render.to_ascii_lowercase();
    let mut needles: Vec<String> = SOURCE_WORDS.iter().map(|w| (*w).to_string()).collect();
    needles.push(format!("secret {SECRET_MODULE_FILE}"));
    needles.push(secret.describe());
    needles.extend(
        secret
            .settings
            .values()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string),
    );
    needles
        .into_iter()
        .filter(|n| !n.is_empty() && lower.contains(&n.to_ascii_lowercase()))
        .collect()
}

pub(super) fn refused_naming_its_source(secret: &SecretRef) -> String {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let text = busbar_kernel::config::secret::resolve_linked_string_at_config(
        secret,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect_err("the reference does not resolve");
    assert!(
        !source_in(&text, secret).is_empty(),
        "the source's own refusal names it, so the scan has something to find: {text}"
    );
    text
}

pub(super) fn assert_clean(
    case: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    secret: &SecretRef,
) {
    let render = rendered(status, headers, body);
    println!("SECRET-SOURCE {case}: {}", render.replace('\n', " | "));
    let found = source_in(&render, secret);
    assert!(
        found.is_empty(),
        "{case}: the caller was handed the secret's source {found:?}:\n{render}"
    );
}

pub(super) fn unset(case: &str) -> String {
    let var = format!("BUSBAR_SECRET_SOURCE_{case}_{}", std::process::id());
    std::env::remove_var(&var);
    var
}

pub(super) fn missing(case: &str) -> String {
    std::env::temp_dir()
        .join(format!(
            "busbar-secret-source-{case}-{}",
            std::process::id()
        ))
        .display()
        .to_string()
}

fn program_section(secret: &SecretRef) -> serde_yaml::Value {
    let mut fs = serde_yaml::Mapping::new();
    fs.insert(
        "transport".into(),
        super::lines::carrier()
            .expect("this build links a line carrier")
            .into(),
    );
    fs.insert("command".into(), "/bin/sh".into());
    fs.insert(
        "cwd".into(),
        std::env::current_dir()
            .expect("an absolute fixture cwd")
            .to_str()
            .expect("a UTF-8 fixture cwd")
            .into(),
    );
    fs.insert(
        "args".into(),
        serde_yaml::Value::Sequence(vec![
            "-c".into(),
            crate::root::door_steps::tests::program_member::script().into(),
        ]),
    );
    let reference = serde_json::json!({
        "module": secret.module,
        "settings": secret.settings,
    });
    let environment: serde_yaml::Mapping =
        serde_yaml::from_str(&format!("{{ env: {{ TOKEN: {reference} }} }}")).expect("a reference");
    for (key, value) in environment {
        fs.insert(key, value);
    }
    fs.insert(
        "pin".into(),
        serde_yaml::from_str("{ mechanism: local_program, key: \"/bin/sh\" }").expect("a pin"),
    );
    fs.insert(
        "tools_allow".into(),
        serde_yaml::from_str(&format!(
            "{{ read_file: {{ schema_hash: \"{}\" }} }}",
            tool_digest()
        ))
        .expect("an approval"),
    );
    let mut tools = serde_yaml::Mapping::new();
    tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
    serde_yaml::Value::Mapping(tools)
}

fn exchange_section(server: &TlsToolServer, secret: &SecretRef) -> serde_yaml::Value {
    let mut tools = server.section();
    tools["fs"]["allow_private"] = true.into();
    tools["fs"]["aud"] = format!("https://127.0.0.1:{}", server.port).into();
    tools["fs"]["tools_allow"]["write_file"] = serde_yaml::from_str(&format!(
        "{{ schema_hash: \"{}\" }}",
        surface("write_digest"),
    ))
    .expect("an approval");
    tools["fs"]["tools_allow"]["stat"] = serde_yaml::from_str(&format!(
        "{{ schema_hash: \"{}\" }}",
        surface("stat_digest"),
    ))
    .expect("an approval");
    tools["fs"]["token_exchange"] = serde_yaml::to_value(serde_json::json!({
        "token_url": "https://as.example/token",
        "subject_token": {
            "module": secret.module,
            "settings": secret.settings,
        },
    }))
    .expect("an exchange with a reference");
    tools
}

async fn call(rig: &Rig) -> (StatusCode, HeaderMap, Vec<u8>) {
    send_headed(
        &rig.router,
        Some(&rig.bound_token()),
        CALL,
        "tools/call",
        Some("fs_read_file"),
    )
    .await
}

fn statement_name(door: busbar_contract::abi::mechanism::door::DoorFn) -> String {
    let row = crate::root::loader::dispatch::LinkedRow::of(door).expect("the door states itself");
    busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("its Statement reads")
        .name
}

fn driven() -> Vec<String> {
    #[allow(unused_mut)]
    let mut names = vec![statement_name(
        crate::root::door_steps::tests::tool_door::line_door(),
    )];
    #[cfg(linked_section_decisions)]
    names.push(super::door_tests::decisions_name());
    #[cfg(linked_section_streams)]
    names.extend(super::door_tests::session_door::name());

    names.extend(super::door_cells_secret_driven());
    #[cfg(linked_driver_proofs)]
    names.push(statement_name(super::hook_seat_tests::pools_door()));
    names
}

#[test]
fn every_linked_door_plane_is_driven() {
    let driven = driven();
    for door in crate::LINKED.plane_doors {
        let name = statement_name(*door);
        assert!(
            driven.contains(&name),
            "the linked door plane '{name}' is not driven by the secret-source scan: add its \
             driver to root/tests/secret_source.rs (a failing secret reference on its members, \
             its caller-facing renders scanned)"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_program_members_unresolved_env_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    let cases = [
        (
            "tools-program-env",
            SecretRef::env(unset("TOOLS_PROGRAM_ENV")),
        ),
        (
            "tools-program-file",
            SecretRef::file(missing("tools-program-file")),
        ),
    ];
    for (instance, secret) in cases {
        refused_naming_its_source(&secret);
        let rig = try_rig_tools(instance, 0, program_section(&secret)).unwrap_or_else(|e| {
            panic!("{instance}: a member's env that did not resolve refuses its spawns, never the compose: {e}")
        });
        let (status, headers, body) = call(&rig).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the tool returns its failure result"
        );
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(answer["id"], 30);
        assert_eq!(answer["result"]["isError"], true);
        assert!(
            answer["result"]["content"][0]["text"]
                .as_str()
                .expect("the tool failure text")
                .contains(busbar_contract::conn::ConnError::Refused.text()),
            "{instance}: the failed spawn reaches the caller as the connector's refusal"
        );
        assert_clean(instance, status, &headers, &body, &secret);
        assert!(
            !String::from_utf8_lossy(&body).contains("from the server"),
            "{instance}: the member is not served"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_program_members_env_gone_by_an_apply_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "tools-program-apply";
    let var = unset("TOOLS_PROGRAM_APPLY");
    std::env::set_var(&var, "busbar-own-program-token");
    let secret = SecretRef::env(&var);
    let rig = try_rig_tools(instance, 0, program_section(&secret)).expect("the door composes");
    let (status, _, body) = call(&rig).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "served while it resolves: {}",
        String::from_utf8_lossy(&body)
    );
    let first: serde_json::Value = serde_json::from_slice(&body).expect("the initial tool reply");
    assert_ne!(
        first["result"]["isError"], true,
        "the initial program call succeeded: {first}"
    );
    assert!(
        first["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("from the server ")),
        "the initial call reached the actual child: {first}"
    );
    let facts = |reply: &serde_json::Value| {
        reply["result"]["content"][0]["text"]
            .as_str()
            .expect("the child result")
            .split_ascii_whitespace()
            .filter_map(|word| word.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = facts(&first);
    assert!(before["pid"].parse::<u32>().is_ok_and(|pid| pid > 0));
    assert_eq!(before["calls"], "1");
    std::env::remove_var(&var);
    refused_naming_its_source(&secret);
    rig.live.apply(&rig.app);
    let (status, headers, body) = call(&rig).await;
    assert_clean(instance, status, &headers, &body, &secret);
    assert_eq!(status, StatusCode::OK, "the spawned program keeps serving");
    assert!(
        String::from_utf8_lossy(&body).contains("from the server"),
        "the member is served by the program spawned while its reference resolved"
    );
    let second: serde_json::Value =
        serde_json::from_slice(&body).expect("the post-apply tool reply");
    assert_ne!(
        second["result"]["isError"], true,
        "the retained child served: {second}"
    );
    let after = facts(&second);
    assert_eq!(
        after["pid"], before["pid"],
        "the same actual child survived apply"
    );
    assert_eq!(after["calls"], "2", "the retained child handled both calls");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_an_unresolved_subject_token_refuses_the_boot_naming_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "tools-exchange-compose";
    let secret = SecretRef::env(unset("TOOLS_EXCHANGE_COMPOSE"));
    refused_naming_its_source(&secret);
    let mut server = TlsToolServer::listing(Arc::new(Mutex::new(three_tools()))).await;
    let Err(refusal) = server.try_rig(instance, exchange_section(&server, &secret), &|app| app)
    else {
        panic!("a subject token that does not resolve refuses the composition");
    };
    println!("SECRET-SOURCE {instance}: compose refused (operator): {refusal}");
    assert!(
        !source_in(&refusal, &secret).is_empty(),
        "the operator's refusal names the source: {refusal}"
    );
    assert!(
        server.heard.try_recv().is_err(),
        "the unresolved subject token refuses before any upstream request"
    );
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_subject_token_gone_by_an_apply_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "tools-exchange-apply";
    let var = unset("TOOLS_EXCHANGE_APPLY");
    std::env::set_var(&var, "busbar-own-subject-token");
    let secret = SecretRef::env(&var);
    let server = TlsToolServer::listing(Arc::new(Mutex::new(three_tools()))).await;
    let rig = server.rig(instance, exchange_section(&server, &secret), &|app| app);
    let (status, _, body) = call(&rig).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "served while it resolves: {}",
        String::from_utf8_lossy(&body)
    );
    let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
    assert_eq!(answer["id"], 30);
    assert_eq!(answer["result"]["content"][0]["text"], "from the server");
    let before = rig.live.current().generation;
    std::env::remove_var(&var);
    refused_naming_its_source(&secret);
    rig.live.apply(&rig.app);
    assert_eq!(
        rig.live.current().generation,
        before,
        "the door keeps the generation it serves"
    );
    let (status, headers, body) = call(&rig).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the retained generation still serves"
    );
    let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
    assert_eq!(answer["id"], 30);
    assert_eq!(answer["result"]["content"][0]["text"], "from the server");
    assert_clean(instance, status, &headers, &body, &secret);
    server.close().await;
}

#[cfg(linked_section_decisions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decisions_an_unresolved_provider_key_refuses_the_boot_naming_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "decisions-key-compose";
    let path = missing(instance);
    let secret = SecretRef::file(path.clone());
    refused_naming_its_source(&secret);
    let (port, _heard) = super::door_tests::far_end().await;
    let Err(refusal) = super::door_tests::serve_keyed(
        &crate::LINKED,
        instance,
        port,
        &format!("{{file: '{path}'}}"),
    )
    .await
    else {
        panic!("a provider key that does not resolve refuses the composition");
    };
    println!("SECRET-SOURCE {instance}: compose refused (operator): {refusal}");
    assert!(
        !source_in(&refusal, &secret).is_empty(),
        "the operator's refusal names the source: {refusal}"
    );
}

#[cfg(linked_section_decisions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decisions_a_provider_key_gone_by_an_apply_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "decisions-key-apply";
    let path = missing(instance);
    std::fs::write(&path, "sk-secret-source-test").expect("the credential file");
    let secret = SecretRef::file(path.clone());
    let (port, _heard) = super::door_tests::far_end().await;
    let serving = super::door_tests::serve_keyed(
        &crate::LINKED,
        instance,
        port,
        &format!("{{file: '{path}'}}"),
    )
    .await
    .expect("the door composes");
    std::fs::remove_file(&path).expect("the credential file goes");
    refused_naming_its_source(&secret);
    let before = serving.live.current().generation;
    serving.live.apply(&serving.handle.load());
    assert_eq!(
        serving.live.current().generation,
        before,
        "the door keeps the generation it serves"
    );
    let response = super::door_tests::send(
        &serving.router,
        super::door_tests::CLAIMED,
        Some(&serving.token),
    )
    .await;
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body reads");
    assert_clean(instance, status, &headers, &body, &secret);
}

#[cfg(linked_section_streams)]
mod session_door_cells {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_door_an_unresolved_provider_key_refuses_the_boot_naming_its_source() {
        let _one = PUBLISHING.lock().await;
        let instance = "session-key-compose";
        let path = missing(instance);
        let secret = SecretRef::file(path.clone());
        refused_naming_its_source(&secret);
        let composed = super::super::door_tests::session_door::session_keyed(
            instance,
            None,
            &format!("{{file: '{path}'}}"),
        )
        .await
        .expect("the build links the session door");
        let Err(refusal) = composed else {
            panic!("a provider key that does not resolve refuses the composition");
        };
        println!("SECRET-SOURCE {instance}: compose refused (operator): {refusal}");
        assert!(
            !source_in(&refusal, &secret).is_empty(),
            "the operator's refusal names the source: {refusal}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_door_a_provider_key_gone_by_an_apply_reaches_the_caller_without_its_source() {
        let _one = PUBLISHING.lock().await;
        let instance = "session-key-apply";
        let path = missing(instance);
        std::fs::write(&path, "sk-secret-source-test").expect("the credential file");
        let secret = SecretRef::file(path.clone());
        let composed = super::super::door_tests::session_door::session_keyed(
            instance,
            None,
            &format!("{{file: '{path}'}}"),
        )
        .await;
        let Some(composed) = composed else {
            let _ = std::fs::remove_file(&path);
            panic!("the build links the session door");
        };
        let serving = composed.expect("the door composes");
        std::fs::remove_file(&path).expect("the credential file goes");
        refused_naming_its_source(&secret);
        let before = serving.live.current().generation;
        serving.live.apply(&serving.app);
        assert_eq!(
            serving.live.current().generation,
            before,
            "the door keeps the generation it serves"
        );
        let response = serving.mint().await;
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body reads");
        assert_clean(instance, status, &headers, &body, &secret);
    }
}

#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pools_door_an_unresolved_provider_key_refuses_the_boot_naming_its_source() {
    use super::hook_seat_tests::{far_end_answering, try_rig, RigOpts, ANSWER};
    let _one = PUBLISHING.lock().await;
    let instance = "pools-key-compose";
    let path = missing(instance);
    let secret = SecretRef::file(path.clone());
    refused_naming_its_source(&secret);
    let far = far_end_answering(200, ANSWER).await;
    let api_key = format!("{{ file: '{path}' }}");
    let Err(refusal) = try_rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            api_key: Some(&api_key),
            ..RigOpts::default()
        },
    )
    .await
    else {
        panic!("a provider key that does not resolve refuses the composition");
    };
    println!("SECRET-SOURCE {instance}: compose refused (operator): {refusal}");
    assert!(
        !source_in(&refusal, &secret).is_empty(),
        "the operator's refusal names the source: {refusal}"
    );
    assert_eq!(
        far.hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing reached the far end"
    );
}

#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pools_door_a_provider_key_gone_by_an_apply_reaches_the_caller_without_its_source() {
    use super::hook_seat_tests::{far_end_answering, rig, RigOpts, ANSWER};
    let _one = PUBLISHING.lock().await;
    let instance = "pools-key-apply";
    let path = missing(instance);
    std::fs::write(&path, "sk-secret-source-test").expect("the credential file");
    let secret = SecretRef::file(path.clone());
    let far = far_end_answering(200, ANSWER).await;
    let api_key = format!("{{ file: '{path}' }}");
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            api_key: Some(&api_key),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.chat().await;
    assert_eq!(
        status,
        200,
        "served while it resolves: {}",
        String::from_utf8_lossy(&body)
    );
    std::fs::remove_file(&path).expect("the credential file goes");
    refused_naming_its_source(&secret);
    let before = rig.generation();
    rig.apply();
    assert_eq!(
        rig.generation(),
        before,
        "the door keeps the generation it serves"
    );
    let (status, headers, body) = rig.chat().await;
    let status = StatusCode::from_u16(status).expect("a status");
    assert_clean(instance, status, &headers, &body, &secret);
    assert_eq!(status, StatusCode::OK, "the kept generation serves");
}

#[path = "secret_source_class.rs"]
mod class;
