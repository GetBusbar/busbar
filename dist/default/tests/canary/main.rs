// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![allow(dead_code)]

#[path = "../common/mod.rs"]
mod common;

mod abi;
mod blackbox;
mod canary;
mod recorder;

use canary::{Canary, Sink};

pub const KINDS: &[&str] = &[
    "provider-key-env-ref",
    "provider-key-file-ref",
    "plugin-setting-interp",
    "export-url-path-token",
    "provider-url-userinfo",
    "provider-url-userinfo-unreachable",
    "admin-token",
    "caller-cookie",
    "caller-custom-auth-header",
    "refusal-inline-api-key",
    "refusal-webhook-auth-header-shape",
    "refusal-webhook-url-query-token",
    "refusal-base-url-userinfo",
    "refusal-signing-key-file-content",
    "abi-secret-refs-file-ref",
    "abi-settings-env-ref",
    "abi-settings-env-template",
    "abi-settings-interp",
    "abi-outbound-credential",
    "abi-passthrough-caller-credential",
];

pub fn canary(kind: &'static str) -> Canary {
    assert!(
        KINDS.contains(&kind),
        "canary kind `{kind}` is not registered"
    );
    Canary::new(kind)
}

#[test]
fn served_node_sinks() {
    let userinfo = canary("provider-url-userinfo");
    let userinfo_form = blackbox::basic_form(&userinfo.value);
    let dead = canary("provider-url-userinfo-unreachable");
    let dead_form = blackbox::basic_form(&dead.value);
    let c = blackbox::NodeCanaries {
        env_ref: canary("provider-key-env-ref").delivered_to("far-end:mock", "mock"),
        file_ref: canary("provider-key-file-ref").delivered_to("far-end:mockfile", "mockfile"),
        interp: canary("plugin-setting-interp"),
        userinfo: userinfo
            .also(userinfo_form)
            .delivered_to("far-end:mockuser", "mockuser"),
        userinfo_dead: dead.also(dead_form),
        admin_token: canary("admin-token"),
        url_path_token: canary("export-url-path-token"),
        caller_cookie: canary("caller-cookie"),
        caller_header: canary("caller-custom-auth-header"),
    };
    let (sinks, notes) = blackbox::node(&c);
    canary::sweep("served-node", &c.all(), &sinks, &notes);
}

#[test]
fn refusal_sinks() {
    let c = blackbox::RefusalCanaries {
        inline_api_key: canary("refusal-inline-api-key"),
        webhook_header_shape: canary("refusal-webhook-auth-header-shape"),
        webhook_url_scheme: canary("refusal-webhook-url-query-token"),
        base_url_userinfo_bad: canary("refusal-base-url-userinfo"),
        signing_key_file: canary("refusal-signing-key-file-content"),
    };
    let (sinks, notes) = blackbox::refusals(&c);
    canary::sweep("refusals", &c.all(), &sinks, &notes);
}

#[test]
fn abi_crossings() {
    let c = abi::AbiCanaries {
        secret_ref_file: canary("abi-secret-refs-file-ref"),
        settings_env_ref: canary("abi-settings-env-ref"),
        settings_template: canary("abi-settings-env-template"),
        settings_interp: canary("abi-settings-interp"),
        outbound_credential: canary("abi-outbound-credential"),
        passthrough: canary("abi-passthrough-caller-credential"),
    };
    let (sinks, notes) = abi::run(&c);
    canary::sweep("abi", &c.all(), &sinks, &notes);
}

#[test]
fn self_test_the_search_finds_what_was_planted() {
    let c = Canary::new("self-test").also("ZW5jb2RlZA".into());
    let other = Canary::new("self-test-absent");
    let sinks = vec![
        Sink::text("log:a", "x", format!("line one\nkey={} here\n", c.value)),
        Sink::raw(
            "abi:b",
            "y",
            format!("{{\"k\":\"{}\"}}", c.value).into_bytes(),
        ),
        Sink::text("log:c", "z", format!("prefix-{}", c.forms[0])),
        Sink::text("log:d", "w", "Basic ZW5jb2RlZA=="),
        Sink::text("far-end:e", "v", c.value.clone()),
        Sink::text("far-end:elsewhere", "another provider", c.value.clone()),
    ];
    let hits = canary::search(&c, &sinks);
    let found: Vec<&str> = hits.iter().map(|h| h.sink.as_str()).collect();
    assert_eq!(
        found,
        [
            "log:a",
            "abi:b",
            "log:c",
            "log:d",
            "far-end:e",
            "far-end:elsewhere"
        ],
        "search records every crossing, including required deliveries: {hits:?}"
    );
    assert_eq!(hits[0].at, "x line 2", "the hit names its line");
    assert!(
        !hits[0].context.contains(&c.value),
        "the report masks the canary"
    );
    assert!(canary::search(&other, &sinks).is_empty());
}

#[test]
fn self_test_unexpected_hits_fail_and_required_deliveries_must_arrive() {
    let c = Canary::new("strict").delivered_to("abi:open.secrets[0]", "receiving-owner");
    let required = Sink::text("abi:open.secrets[0]", "receiving-owner", c.value.clone());
    assert!(canary::judge(&c, &canary::search(&c, &[required.clone()])).ok);
    assert!(
        !canary::judge(&c, &[]).ok,
        "a missing required delivery cannot pass"
    );
    for other in [
        Sink::text("abi:open.secrets[0]", "different-owner", c.value.clone()),
        Sink::text("abi:open.settings", "receiving-owner", c.value.clone()),
        Sink::text("log:node", "receiving-owner", c.value.clone()),
        Sink::text("refusal:open", "receiving-owner", c.value.clone()),
    ] {
        let hits = canary::search(&c, &[required.clone(), other]);
        assert!(
            !canary::judge(&c, &hits).ok,
            "an unexpected secret crossing always fails: {hits:?}"
        );
    }
    let strict = Canary::new("no-deliveries");
    let hits = canary::search(
        &strict,
        &[Sink::text("log:node", "host", strict.value.clone())],
    );
    assert!(!canary::judge(&strict, &hits).ok);
    assert!(canary::judge(&strict, &[]).ok);
    for kind in KINDS {
        assert_eq!(
            KINDS.iter().filter(|k| *k == kind).count(),
            1,
            "one registered kind: {kind}"
        );
    }
}

#[test]
fn self_test_a_black_box_sink_finds_a_planted_value() {
    let c = Canary::new("self-test-provider-name");
    let dir = blackbox::scratch("self-test");
    std::fs::write(dir.join("providers.yaml"), "").expect("providers.yaml");
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:0\"\nproviders_file: \"{}\"\nproviders: {{}}\n\
             models:\n  m: {{ provider: {} }}\nstore: {{module: memory}}\n",
            dir.join("providers.yaml").display(),
            c.value
        ),
    )
    .expect("config.yaml");
    let out = std::process::Command::new(common::boot::exe())
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env_remove("BUSBAR_PROVIDERS")
        .output()
        .expect("run busbar --validate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    let hits = canary::search(&c, &[Sink::text("validate", "models", text.clone())]);
    assert!(
        !out.status.success() && !hits.is_empty(),
        "the unknown provider name is echoed by the --validate refusal and the search finds it: \
         {text}"
    );
}

#[test]
fn self_test_the_shim_records_a_planted_crossing() {
    let c = Canary::new("self-test-shim");
    let (sinks, _) = abi::run(&abi::AbiCanaries {
        secret_ref_file: c.clone(),
        settings_env_ref: Canary::new("self-test-unused-1"),
        settings_template: Canary::new("self-test-unused-2"),
        settings_interp: Canary::new("self-test-unused-3"),
        outbound_credential: Canary::new("self-test-unused-4"),
        passthrough: Canary::new("self-test-unused-5"),
    });
    let hits = canary::search(&c, &sinks);
    let (signing_secret_sink, signing_secret_plugin) = abi::signing_secret_crossing();
    assert!(
        hits.iter()
            .any(|h| h.sink == signing_secret_sink && h.at == signing_secret_plugin),
        "the shim records the planted secret crossing into `open`: {hits:?}"
    );
}
