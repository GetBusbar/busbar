// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CREDENTIAL CANARY HARNESS. MEASUREMENT ONLY: it changes
//! no production code and no behaviour.
//!
//! The owner's rule is "credentials never leave the secret boundary". No unit test can prove that
//! property: it is about every sink at once. So this binary PLANTS a unique fake credential (a
//! canary, `CANARY-<kind>-<random hex>`) through each credential input kind busbar resolves, drives
//! the node, and SEARCHES every sink a black box can see for each one:
//!
//! * the served node (`blackbox::node`): its whole log (every tracing line, any panic message),
//!   every admin and data-plane response, the exported request log, `--validate` output, and what
//!   each far end received;
//! * refusals (`blackbox::refusals`): `--validate` over configs built to be refused around a canary;
//! * the plugin ABI (`abi::run`): every byte the recording host-table shim (`recorder`) saw cross
//!   between host and plugin, for a linked and a dropped-in door (settings, declared secrets, outbound and passthrough
//!   credentials).
//!
//! EVERY CANARY IS XFAIL BY DEFAULT where it leaks today: [`EXPECT`] marks each kind
//! `Expect::Leaks` (passes while its hits exist, listing them) or `Expect::Clean` (any hit fails).
//! A `Leaks` canary that stops leaking still passes and says "NOW CLEAN: flip to Expect::Clean";
//! flipping it makes the fix permanent. The baseline may only shrink.
//!
//! The listing of every hit is written to `target/canary-report/<scenario>.txt`.
#![cfg(unix)]
#![allow(dead_code)]

#[path = "../common/mod.rs"]
mod common;

mod abi;
mod blackbox;
mod canary;
mod recorder;

use canary::{Canary, Expect, Sink};

/// THE EXPECTATION TABLE: one row per planted kind, what it does TODAY. Flip a row to
/// `Expect::Clean` when its leak is fixed (the harness says when); never flip one back.
pub const EXPECT: &[(&str, Expect)] = &[
    // ── the served node ──
    // A provider key through an env / file SecretRef: only its own far end sees it.
    ("provider-key-env-ref", Expect::Clean),
    ("provider-key-file-ref", Expect::Clean),
    // `${VAR}` into the request-log webhook's auth header and a token in the webhook URL's path: no
    // delivery is observed inside the sweep's window today, and a delivery failure logs the URL, so
    // these stay XFAIL until a fix pins them.
    ("plugin-setting-interp", Expect::Leaks),
    ("export-url-path-token", Expect::Leaks),
    // A provider base_url's userinfo password: only its own far end sees it (as Basic).
    ("provider-url-userinfo", Expect::Clean),
    ("provider-url-userinfo-unreachable", Expect::Clean),
    ("admin-token", Expect::Clean),
    ("caller-cookie", Expect::Clean),
    // The caller's custom auth header is relayed to every far end.
    ("caller-custom-auth-header", Expect::Leaks),
    // ── refusals ──
    ("refusal-inline-api-key", Expect::Clean),
    // Serde's `invalid type: string "<value>"` carries the header value into the refusal.
    ("refusal-webhook-auth-header-shape", Expect::Leaks),
    // Both ACCEPTED by `--validate` today (the report notes it), so nothing echoes them.
    ("refusal-webhook-url-query-token", Expect::Clean),
    ("refusal-base-url-userinfo", Expect::Clean),
    ("refusal-signing-key-file-content", Expect::Clean),
    // ── the plugin ABI (credentials cross it by design today) ──
    ("abi-secret-refs-file-ref", Expect::Leaks),
    ("abi-settings-env-ref", Expect::Leaks),
    // An `env-template` ref at a plugin setting's top level is NOT resolved for an auth plugin
    // today: the raw reference crosses and the plugin refuses it, so its value never crosses.
    ("abi-settings-env-template", Expect::Clean),
    ("abi-settings-interp", Expect::Leaks),
    ("abi-outbound-credential", Expect::Leaks),
    ("abi-passthrough-caller-credential", Expect::Leaks),
];

/// A fresh canary for `kind`, under its [`EXPECT`] row.
pub fn canary(kind: &'static str) -> Canary {
    let expect = EXPECT
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, e)| *e)
        .unwrap_or_else(|| panic!("canary kind `{kind}` has no EXPECT row"));
    Canary::new(kind, expect)
}

/// THE SERVED NODE: env/file refs, `${VAR}` into a plugin setting, URL userinfo, the admin token, an
/// export URL's path token and the caller's own credentials, searched in every black-box sink.
#[test]
fn served_node_sinks() {
    let userinfo = canary("provider-url-userinfo");
    let userinfo_form = blackbox::basic_form(&userinfo.value);
    let dead = canary("provider-url-userinfo-unreachable");
    let dead_form = blackbox::basic_form(&dead.value);
    let c = blackbox::NodeCanaries {
        // A provider key reaching ITS OWN far end is the designed delivery, not a leak.
        env_ref: canary("provider-key-env-ref").delivered_to("far-end:mock"),
        file_ref: canary("provider-key-file-ref").delivered_to("far-end:mockfile"),
        interp: canary("plugin-setting-interp"),
        userinfo: userinfo
            .also(userinfo_form)
            .delivered_to("far-end:mockuser"),
        userinfo_dead: dead.also(dead_form),
        admin_token: canary("admin-token"),
        url_path_token: canary("export-url-path-token"),
        caller_cookie: canary("caller-cookie"),
        caller_header: canary("caller-custom-auth-header"),
    };
    let (sinks, notes) = blackbox::node(&c);
    canary::sweep("served-node", &c.all(), &sinks, &notes);
}

/// REFUSALS: `--validate` over configs refused around a canary.
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

/// THE PLUGIN ABI: what crosses between host and plugin, recorded by the shim.
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

// ── SELF-TESTS: the harness is not vacuous ─────────────────────────────────────────────────────

/// The search finds a planted value in every sink shape (a line of text, bytes, an encoded form),
/// skips a designed delivery, and finds nothing that was not planted.
#[test]
fn self_test_the_search_finds_what_was_planted() {
    let c = Canary::new("self-test", Expect::Clean).also("ZW5jb2RlZA".into());
    let other = Canary::new("self-test-absent", Expect::Clean);
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
    ];
    let hits = canary::search(&c.clone().delivered_to("far-end:e"), &sinks);
    let found: Vec<&str> = hits.iter().map(|h| h.sink.as_str()).collect();
    assert_eq!(found, ["log:a", "abi:b", "log:c", "log:d"], "{hits:?}");
    assert_eq!(hits[0].at, "x line 2", "the hit names its line");
    assert!(
        !hits[0].context.contains(&c.value),
        "the report masks the canary"
    );
    assert!(canary::search(&other, &sinks).is_empty());
}

/// The verdicts: a CLEAN canary that leaks fails; a LEAKS canary that is clean passes and says to
/// flip it; a LEAKS canary that leaks passes, listing its hits.
#[test]
fn self_test_the_verdicts_hold_the_expectation() {
    let hit = vec![canary::Hit {
        sink: "log:a".into(),
        at: "x".into(),
        context: "c".into(),
    }];
    let strict = Canary::new("strict", Expect::Clean);
    let xfail = Canary::new("xfail", Expect::Leaks);
    assert!(!canary::judge(&strict, &hit).ok);
    assert!(canary::judge(&strict, &[]).ok);
    let v = canary::judge(&xfail, &hit);
    assert!(v.ok && v.text.contains("XFAIL") && v.text.contains("log:a"));
    let v = canary::judge(&xfail, &[]);
    assert!(v.ok && v.text.contains("flip to Expect::Clean"));
    for (kind, _) in EXPECT {
        assert_eq!(
            EXPECT.iter().filter(|(k, _)| k == kind).count(),
            1,
            "one EXPECT row per kind: {kind}"
        );
    }
}

/// The black-box capture is live: a value planted where the binary is known to print it back (a
/// model's unknown provider NAME, not a credential) is found in the captured `--validate` refusal.
#[test]
fn self_test_a_black_box_sink_finds_a_planted_value() {
    let c = Canary::new("self-test-provider-name", Expect::Leaks);
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

/// The recording shim is live: a value planted as a `secret_refs` setting of a wrapped door is
/// recorded crossing into the plugin's `open`, and found there by the search.
#[test]
fn self_test_the_shim_records_a_planted_crossing() {
    let c = Canary::new("self-test-shim", Expect::Leaks);
    let (sinks, _) = abi::run(&abi::AbiCanaries {
        secret_ref_file: c.clone(),
        settings_env_ref: Canary::new("self-test-unused-1", Expect::Leaks),
        settings_template: Canary::new("self-test-unused-2", Expect::Leaks),
        settings_interp: Canary::new("self-test-unused-3", Expect::Leaks),
        outbound_credential: Canary::new("self-test-unused-4", Expect::Leaks),
        passthrough: Canary::new("self-test-unused-5", Expect::Leaks),
    });
    let hits = canary::search(&c, &sinks);
    // Which `secrets[i]` slot it rides is the wrapped door's declared order (webhook-signature's dev
    // declares its secret fields, so the planted reference is no longer the first): the proof is
    // that it is recorded crossing into `open` as a secret at all.
    assert!(
        hits.iter()
            .any(|h| h.sink.starts_with("abi:host->plugin:op:open.secrets[")),
        "the shim records the planted secret crossing into `open`: {hits:?}"
    );
}
