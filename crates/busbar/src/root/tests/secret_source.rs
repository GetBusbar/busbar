// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SECRET'S SOURCE NEVER REACHES A CALLER (coordinator ruling 2026-10-07, the cell the retired tool-plane crate's
//! `credential_secret_leak_tests` was until #511 deleted it): on every door plane this build links,
//! a secret reference that does not resolve leaves the caller-facing status line, headers and body
//! free of its source (the variable's name, the file's path, the reference as written) and of the
//! words a source's refusal is phrased in ("environment variable", "secret file", "is unset", "No
//! such file"). The operator's surfaces keep naming the source (the boot's and the apply's text,
//! 1.5.5's bytes): the boot refusal is asserted to name it, so a fix that blinded the operator too
//! would be caught here as well.
//!
//! Each linked door is driven where a failing reference can meet a caller:
//! * at REQUEST time, a member program whose `env` reference does not resolve (the loader declares
//!   no such member; the open naming it is the connector's fixed-class refusal), unresolvable at
//!   compose or after an apply;
//! * at COMPOSE time, a member's credential (a token exchange's subject token, a provider's
//!   `api_key`): the boot is refused with the operator's text and nothing is served;
//! * across an APPLY, the same credential gone: the door keeps the generation it serves, and the
//!   caller is served by it.
//!
//! [`every_linked_door_plane_is_driven`] keeps the set whole: a door this build links (a plane
//! flipped onto the driver: a2a, streaming) with no driver here fails until it has one.

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use busbar_contract::secret_ref::SecretRef;

use crate::root::door_steps::tests::tool_door::{
    send_headed, surface, three_tools, tool_digest, tool_server_listing, try_rig_tools, Rig, CALL,
};
use crate::root::serve::planes_tests::{Published, PUBLISHING};

/// The words a secret source's own refusal is phrased in (the linked `env` and `file` sources',
/// the OS's), matched without case.
const SOURCE_WORDS: [&str; 4] = [
    "environment variable",
    "secret file",
    "is unset",
    "no such file",
];

/// Everything a caller is handed: the status line, every header, the body.
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

/// What of `secret`'s source `render` carries: its source's words, the reference as written and
/// every setting it names (the variable, the path). Empty when the render is clean.
fn source_in(render: &str, secret: &SecretRef) -> Vec<String> {
    let lower = render.to_ascii_lowercase();
    let mut needles: Vec<String> = SOURCE_WORDS.iter().map(|w| (*w).to_string()).collect();
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

/// THE CONTROL: `secret` does not resolve, and the text its source refuses with names it (the
/// operator's text), so a clean render is a render that withheld it, not one that never had it.
fn refused_naming_its_source(secret: &SecretRef) -> String {
    let text = busbar_kernel::config::secret::resolve_linked_string(secret)
        .expect_err("the reference does not resolve");
    assert!(
        !source_in(&text, secret).is_empty(),
        "the source's own refusal names it, so the scan has something to find: {text}"
    );
    text
}

/// The caller's render is clean of `secret`'s source; the measurement row is printed.
fn assert_clean(
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

/// A variable name no environment sets: one per case (the tests of one binary share a process).
fn unset(case: &str) -> String {
    let var = format!("BUSBAR_SECRET_SOURCE_{case}_{}", std::process::id());
    std::env::remove_var(&var);
    var
}

/// A path no file is at.
fn missing(case: &str) -> String {
    std::env::temp_dir()
        .join(format!(
            "busbar-secret-source-{case}-{}",
            std::process::id()
        ))
        .display()
        .to_string()
}

/// A member program's `env` secret reference resolves through the linked secret plugins, as the
/// root's boot installs them (the first install holds; this is the same one).
fn member_secrets_installed() {
    let _ = crate::root::loader::dispatch::install_member_secrets(
        busbar_kernel::config::secret::resolve_linked_string,
    );
}

/// The tool door's `tools:` section: one member, `fs`, that is the program
/// `program_member::script` serves, its environment's `TOKEN` the reference `secret`.
fn program_section(secret: &SecretRef) -> serde_yaml::Value {
    let mut fs = serde_yaml::Mapping::new();
    fs.insert("transport".into(), "stdio".into());
    fs.insert("command".into(), "/bin/sh".into());
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
        serde_yaml::from_str("{ mechanism: pinned_pubkey, key: \"sha256/K=\" }").expect("a pin"),
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

/// The tool door's `tools:` section: one member, `fs`, at loopback `port`, bound by a token
/// exchange whose subject token is the reference `secret`.
fn exchange_section(port: u16, secret: &SecretRef) -> serde_yaml::Value {
    let mut tools: serde_yaml::Value = serde_yaml::from_str(&format!(
        "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
         pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
         allow_private: true\n  aud: \"http://127.0.0.1:{port}\"\n  \
         token_exchange:\n    token_url: \"https://as.example/token\"\n  \
         tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n    \
         write_file: {{ schema_hash: \"{}\" }}\n    stat: {{ schema_hash: \"{}\" }}\n",
        tool_digest(),
        surface("write_digest"),
        surface("stat_digest"),
    ))
    .expect("a section");
    tools["fs"]["token_exchange"]["subject_token"] = serde_yaml::to_value(serde_json::json!({
        "module": secret.module,
        "settings": secret.settings,
    }))
    .expect("a reference");
    tools
}

/// One `tools/call` through `rig`'s door, by its own key.
async fn call(rig: &Rig) -> (StatusCode, HeaderMap, Vec<u8>) {
    send_headed(
        &rig.router,
        Some(&rig.token),
        CALL,
        "tools/call",
        Some("fs_read_file"),
    )
    .await
}

/// The Statement name a linked door states.
fn statement_name(door: busbar_contract::abi::mechanism::door::DoorFn) -> String {
    let row = crate::root::loader::dispatch::LinkedRow::of(door).expect("the door states itself");
    busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("its Statement reads")
        .name
}

/// The doors this file drives, by Statement name.
fn driven() -> Vec<String> {
    let mut names = vec![statement_name(
        crate::root::door_steps::tests::tool_door::line_door(),
    )];
    #[cfg(feature = "plane-decisions")]
    names.push(super::door_tests::decisions_name());
    names
}

/// EVERY DOOR THIS BUILD LINKS IS DRIVEN HERE: a plane flipped onto the driver (a2a, streaming, the
/// llm fold) joins the scan, or this fails naming it.
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

/// THE TOOL DOOR, REQUEST TIME: a member program whose `env` reference does not resolve (an unset variable,
/// a missing file) is no member, and a caller's call to its tool is refused with nothing of the
/// reference's source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_program_members_unresolved_env_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    member_secrets_installed();
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
        let _published = Published(instance);
        refused_naming_its_source(&secret);
        let rig = try_rig_tools(instance, 0, program_section(&secret)).unwrap_or_else(|e| {
            panic!("{instance}: a member's env is not resolved at compose: {e}")
        });
        let (status, headers, body) = call(&rig).await;
        assert_clean(instance, status, &headers, &body, &secret);
        assert!(
            !String::from_utf8_lossy(&body).contains("from the server"),
            "{instance}: the member is not served"
        );
    }
}

/// THE TOOL DOOR, ACROSS AN APPLY: a member program served while its `env` reference resolved, the variable
/// then gone and the configuration applied: the refreshed door holds no such member, and the
/// caller's call is refused with nothing of its source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_program_members_env_gone_by_an_apply_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    member_secrets_installed();
    let instance = "tools-program-apply";
    let _published = Published(instance);
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
    std::env::remove_var(&var);
    refused_naming_its_source(&secret);
    rig.live.apply(&rig.app);
    let (status, headers, body) = call(&rig).await;
    assert_clean(instance, status, &headers, &body, &secret);
    assert!(
        !String::from_utf8_lossy(&body).contains("from the server"),
        "the refreshed door holds no such member"
    );
}

/// THE TOOL DOOR, COMPOSE TIME: a token exchange whose subject token does not resolve refuses the boot with
/// the operator's text, which names the source (1.5.5's bytes); nothing is served to a caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_an_unresolved_subject_token_refuses_the_boot_naming_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "tools-exchange-compose";
    let _published = Published(instance);
    let secret = SecretRef::env(unset("TOOLS_EXCHANGE_COMPOSE"));
    refused_naming_its_source(&secret);
    let (port, _heard) = tool_server_listing(Arc::new(std::sync::Mutex::new(three_tools()))).await;
    let Err(refusal) = try_rig_tools(instance, port, exchange_section(port, &secret)) else {
        panic!("a subject token that does not resolve refuses the composition");
    };
    println!("SECRET-SOURCE {instance}: compose refused (operator): {refusal}");
    assert!(
        !source_in(&refusal, &secret).is_empty(),
        "the operator's refusal names the source: {refusal}"
    );
}

/// THE TOOL DOOR, ACROSS AN APPLY: a token-exchange member served while its subject token resolved, the
/// variable then gone and the configuration applied: the door keeps the generation it serves (the
/// operator is told in the log), and the caller is served by it, its render clean of the source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_subject_token_gone_by_an_apply_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "tools-exchange-apply";
    let _published = Published(instance);
    let var = unset("TOOLS_EXCHANGE_APPLY");
    std::env::set_var(&var, "busbar-own-subject-token");
    let secret = SecretRef::env(&var);
    let (port, _heard) = tool_server_listing(Arc::new(std::sync::Mutex::new(three_tools()))).await;
    let rig =
        try_rig_tools(instance, port, exchange_section(port, &secret)).expect("the door composes");
    let (status, _, body) = call(&rig).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "served while it resolves: {}",
        String::from_utf8_lossy(&body)
    );
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
    assert_clean(instance, status, &headers, &body, &secret);
}

/// DECISIONS, COMPOSE TIME: a provider whose `api_key` does not resolve refuses the boot with the
/// operator's text, which names the source; nothing is served to a caller.
#[cfg(feature = "plane-decisions")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decisions_an_unresolved_provider_key_refuses_the_boot_naming_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "decisions-key-compose";
    let _published = Published(instance);
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

/// DECISIONS, ACROSS AN APPLY: a provider served while its `api_key` file was there, the file then
/// gone and the configuration applied: the door keeps the generation it serves, and the caller is
/// served by it, its render clean of the source.
#[cfg(feature = "plane-decisions")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decisions_a_provider_key_gone_by_an_apply_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "decisions-key-apply";
    let _published = Published(instance);
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
