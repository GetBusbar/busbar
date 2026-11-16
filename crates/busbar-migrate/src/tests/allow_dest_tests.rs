// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALLOW-DEST (IF §14, §12.10 item 3), a core-config fixture: the hosts are core's own providers,
//! judged by `config::allow_dest` with a fixed resolver; no plugin supplies one.

use std::net::IpAddr;

use busbar_contract::yaml::{self, MappingExt, Value, ValueExt};

use crate::allow_dest;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// The fixed resolver: what each test host answers.
fn answers(host: &str) -> Result<Vec<IpAddr>, String> {
    match host {
        "ollama.lan" => Ok(vec![ip("10.0.0.7")]),
        "vllm.lan" => Ok(vec![ip("192.168.1.9"), ip("127.0.0.1")]),
        "api.example.com" => Ok(vec![ip("93.184.216.34")]),
        "mixed.lan" => Ok(vec![ip("10.0.0.8"), ip("93.184.216.35")]),
        "meta.lan" => Ok(vec![ip("169.254.169.254")]),
        "empty.lan" => Ok(Vec::new()),
        _ => Err("no such host".to_owned()),
    }
}

fn decide(config: &str, catalog: &str) -> (Vec<String>, Vec<String>) {
    let resolved: Value = yaml::from_str(config).expect("config parses");
    let catalog: Value = yaml::from_str(catalog).expect("catalog parses");
    let mut after = resolved.clone();
    let root = after.as_mapping_mut().expect("a mapping");
    let mut report = Vec::new();
    allow_dest::run(root, &resolved, Some(&catalog), answers, &mut report);
    let listed = after
        .get("advanced")
        .and_then(|advanced| advanced.get("allow_destinations"))
        .and_then(ValueExt::as_sequence)
        .map(|list| {
            list.iter()
                .filter_map(|host| host.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    (listed, report)
}

#[test]
fn a_private_provider_a_model_names_is_allowed_and_a_public_one_needs_no_entry() {
    let (listed, report) = decide(
        "models:\n  local: {provider: ollama}\n  cloud: {provider: hosted}\n",
        "ollama: {base_url: 'http://ollama.lan:11434/v1'}\nhosted: {base_url: 'https://api.example.com'}\n",
    );
    assert_eq!(listed, ["ollama.lan"]);
    assert_eq!(report.len(), 2, "one line per decision: {report:?}");
    assert!(report
        .iter()
        .any(|line| line.contains("api.example.com") && line.contains("every answer public")));
}

#[test]
fn a_catalog_entry_no_model_names_adds_nothing_but_an_authored_one_is_a_candidate() {
    let (listed, _) = decide(
        "models: {}\n",
        "ollama: {base_url: 'http://ollama.lan/v1'}\n",
    );
    assert!(listed.is_empty(), "{listed:?}");
    let (listed, _) = decide(
        "providers:\n  mine: {base_url: 'http://ollama.lan/v1', token_url: 'http://vllm.lan/token'}\n",
        "{}\n",
    );
    assert_eq!(listed, ["ollama.lan", "vllm.lan"]);
}

#[test]
fn the_authored_key_wins_over_the_catalog_and_a_host_is_decided_once() {
    let (listed, report) = decide(
        "providers:\n  p: {base_url: 'http://ollama.lan/v1'}\nmodels:\n  a: {provider: p}\n  b: {provider: p}\n",
        "p: {base_url: 'https://api.example.com', token_url: 'http://ollama.lan/t'}\n",
    );
    assert_eq!(listed, ["ollama.lan"]);
    assert_eq!(report.len(), 1, "{report:?}");
}

#[test]
fn an_entry_already_listed_is_left_and_never_resolved() {
    let (listed, report) = decide(
        "advanced: {allow_destinations: ['OLLAMA.LAN.']}\nmodels: {m: {provider: p}}\n",
        "p: {base_url: 'http://ollama.lan/v1'}\n",
    );
    assert_eq!(listed, ["OLLAMA.LAN."]);
    assert!(report[0].contains("already listed"), "{report:?}");
}

#[test]
fn metadata_mixed_unresolved_and_silent_hosts_are_never_added() {
    for host in [
        "meta.lan",
        "mixed.lan",
        "empty.lan",
        "gone.lan",
        "169.254.169.254",
        "metadata.google.internal",
    ] {
        let (listed, report) = decide(
            "models: {m: {provider: p}}\n",
            &format!("p: {{base_url: 'http://{host}/v1'}}\n"),
        );
        assert!(listed.is_empty(), "{host}: {listed:?}");
        assert_eq!(report.len(), 1, "{host}: a line names why: {report:?}");
    }
}

#[test]
fn literals_and_localhost_are_judged_without_the_resolver() {
    let (listed, _) = decide(
        "models: {m: {provider: p}, n: {provider: q}, o: {provider: r}}\n",
        "p: {base_url: 'http://127.0.0.1:8000'}\nq: {base_url: 'http://localhost:9'}\nr: {base_url: 'http://[::1]:7/'}\n",
    );
    assert_eq!(listed, ["127.0.0.1", "localhost", "::1"]);
}

#[test]
fn nothing_is_written_when_no_host_is_added() {
    let resolved: Value = yaml::from_str("models: {m: {provider: p}}\n").unwrap();
    let catalog: Value = yaml::from_str("p: {base_url: 'https://api.example.com'}\n").unwrap();
    let mut after = resolved.clone();
    let mut report = Vec::new();
    allow_dest::run(
        after.as_mapping_mut().unwrap(),
        &resolved,
        Some(&catalog),
        answers,
        &mut report,
    );
    assert!(
        yaml::same_tree(&resolved, &after),
        "the document is untouched"
    );
    assert!(after.as_mapping().unwrap().get_key("advanced").is_none());
}
