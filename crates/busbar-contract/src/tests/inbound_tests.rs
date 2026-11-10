// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate as busbar_contract;
use crate::abi::host::conn::connector::DIRECTION_OUTBOUND;
use serde_json::json;

fn need(direction: u32, transport: &str, target_from: &str) -> ReadNeed {
    ReadNeed {
        direction,
        egress_class: 0,
        transport: transport.into(),
        auth: String::new(),
        target_from: target_from.into(),
        trust_from: String::new(),
        details: busbar_contract::abi::mechanism::rendering::ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

fn settings(value: serde_json::Value) -> Settings {
    serde_json::from_value(value).unwrap()
}

#[test]
fn only_declared_inbound_paths_are_interpreted_and_indices_are_preserved() {
    let held = settings(
        json!({"private": {"listen":"secret-canary"},"server":{"edge":{"listen":"127.0.0.1:8443"}}}),
    );
    let claims = interpret(
        &held,
        &[
            need(DIRECTION_OUTBOUND, "opaque", "private"),
            need(DIRECTION_INBOUND, "opaque", "server.edge"),
        ],
    )
    .unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].need, 1);
    assert_eq!(claims[0].path, "server.edge");
    let binding = claims[0].binding.as_ref().unwrap();
    assert_eq!(binding.listen, "127.0.0.1:8443".parse().unwrap());
    assert_eq!(binding.max_conns, DEFAULT_MAX_CONNS);
    assert!(!format!("{claims:?}").contains("secret-canary"));
}

#[test]
fn omitted_listener_and_explicit_null_have_different_admission() {
    let needs = [need(DIRECTION_INBOUND, "opaque", "listen")];
    assert!(interpret(&Settings::default(), &needs).unwrap()[0]
        .binding
        .is_none());
    assert_eq!(
        interpret(&settings(json!({"listen":null})), &needs).unwrap_err(),
        "listen.listen: not set"
    );
}

#[test]
fn explicit_cleartext_and_connection_limits_survive_as_policy_metadata() {
    let needs = [need(DIRECTION_INBOUND, "opaque", "server")];
    let implicit = interpret(
        &settings(json!({"server":{"listen":"127.0.0.1:8080"}})),
        &needs,
    )
    .unwrap();
    let explicit = interpret(
        &settings(json!({"server":{"listen":"127.0.0.1:8080","tls":null,"max_conns":1024}})),
        &needs,
    )
    .unwrap();
    let implicit = implicit[0].binding.as_ref().unwrap();
    let explicit = explicit[0].binding.as_ref().unwrap();
    assert_eq!(implicit.listen, explicit.listen);
    assert_eq!(implicit.tls, explicit.tls);
    assert_eq!(implicit.max_conns, explicit.max_conns);
    assert!(!implicit.tls_explicit && !implicit.max_conns_explicit);
    assert!(explicit.tls_explicit && explicit.max_conns_explicit);
}

#[test]
fn tls_is_typed_and_unrecognized_fields_cannot_cross_admission() {
    let needs = [need(DIRECTION_INBOUND, "opaque", "server")];
    let mut document = json!({"server":{"listen":"127.0.0.1:8443","tls":{
        "cert":{"module":"source","settings":{"id":"cert"}},
        "key":{"module":"source","settings":{"id":"key"}}
    }}});
    let claims = interpret(&settings(document.clone()), &needs).unwrap();
    assert_eq!(
        claims[0]
            .binding
            .as_ref()
            .unwrap()
            .tls
            .as_ref()
            .unwrap()
            .key
            .module,
        "source"
    );
    document["server"]["tls"]["private-canary"] = json!("secret-canary");
    let error = interpret(&settings(document), &needs).unwrap_err();
    assert!(error.starts_with("server.tls: invalid TLS configuration"));
    assert!(!error.contains("canary"));
}

#[test]
fn malformed_addresses_and_limits_fail_without_echoing_values() {
    let needs = [need(DIRECTION_INBOUND, "opaque", "server")];
    for document in [
        json!({"server":{"listen":"secret-canary"}}),
        json!({"server":{"listen":"127.0.0.1:8080","max_conns":0}}),
    ] {
        let error = interpret(&settings(document), &needs).unwrap_err();
        assert!(!error.contains("secret-canary"));
    }
}

#[test]
fn an_inbound_need_must_declare_its_settings_path() {
    let error = interpret(
        &Settings::default(),
        &[need(DIRECTION_INBOUND, "opaque", "")],
    )
    .unwrap_err();
    assert!(error.contains("names no settings block"));
}
