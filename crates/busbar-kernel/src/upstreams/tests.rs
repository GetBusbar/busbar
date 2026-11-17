// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Upstream typing (IF §12.1, §12.18): the entry grammar, `StdioCommand.cwd`/`ProgramPin` and the local_program
//! rules, the stdio refusal, the binding `upstreams.<name>.auth` names, and the table's lookup.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::config::UpstreamCreds;
use busbar_contract::json::{json, JsonContainerTrait as _, Value};
use busbar_contract::secret_ref::SecretRef;

use super::{
    implicit_instance, ConfiguredUpstreams, ProgramPin, UpstreamAuth, UpstreamDef, Upstreams,
    DEFAULT_IDLE_S,
};
use crate::config::min3::{UpstreamAuthCfg, UpstreamAuthForm, UpstreamCfg};
use crate::plugin_config::TrustAnchor;

const PIN_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";

fn digest() -> [u8; 32] {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ][i % 16];
    }
    d
}

fn anchor(pem: &str) -> Result<Arc<TrustAnchor>, String> {
    if pem.contains("BEGIN CERTIFICATE") {
        Ok(Arc::new(TrustAnchor {
            der: vec![vec![1, 2, 3]],
            sha256: [7; 32],
        }))
    } else {
        Err("is not a PEM certificate bundle".into())
    }
}

fn secret(path: &str) -> Value {
    json!({"module": "file", "settings": {"path": path}})
}

fn typed(name: &str, entry: Value) -> Result<UpstreamDef, Vec<String>> {
    UpstreamDef::from_config(name, &entry, &UpstreamCfg::default(), &anchor)
}

fn typed_with(name: &str, entry: Value, cfg: &UpstreamCfg) -> Result<UpstreamDef, Vec<String>> {
    UpstreamDef::from_config(name, &entry, cfg, &anchor)
}

fn refusals(name: &str, entry: Value) -> String {
    match typed(name, entry) {
        Ok(_) => panic!("`upstreams.{name}` was accepted"),
        Err(why) => {
            assert!(!why.is_empty());
            why.join("\n")
        }
    }
}

fn bearer() -> UpstreamCfg {
    UpstreamCfg {
        auth: Some(UpstreamAuthCfg {
            form: UpstreamAuthForm::Bearer(SecretRef::None),
            cache_max_s: None,
        }),
        upstream_credentials: None,
        resource: None,
    }
}

#[test]
fn a_network_upstream_types_its_url_pins_identity_and_trust() {
    let def = typed(
        "planner",
        json!({
            "url": "https://agent.example/a2a",
            "tls": {
                "pin_spki": [format!("sha256:{PIN_HEX}"), PIN_HEX],
                "client_identity": secret("/run/id.pem"),
                "trust": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            },
        }),
    )
    .expect("a complete network upstream is accepted");
    assert_eq!(&*def.name, "planner");
    assert_eq!(def.url.as_deref(), Some("https://agent.example/a2a"));
    assert!(def.command.is_none());
    assert_eq!(
        def.tls.pin_spki,
        vec![digest()],
        "both spellings decode, the duplicate is one pin"
    );
    assert!(matches!(
        def.tls.client_identity,
        Some(SecretRef::Source(_))
    ));
    assert_eq!(def.tls.trust.as_ref().map(|t| t.sha256), Some([7; 32]));
    assert!(def.auth.is_none(), "no `auth` is no credential");
}

#[test]
fn a_stdio_upstream_types_argv_env_and_cwd_and_defaults_idle_and_pin() {
    let def = typed(
        "files",
        json!({"command": {
            "argv": ["/opt/mcp/files", "--root", "/srv"],
            "env": {"API_KEY": secret("/run/key"), "MODE": "none"},
            "cwd": "/srv/mcp",
        }}),
    )
    .expect("a stdio upstream is accepted");
    assert!(def.url.is_none());
    let command = def.command.expect("the command is kept");
    assert_eq!(
        command.argv.iter().map(|a| &**a).collect::<Vec<_>>(),
        ["/opt/mcp/files", "--root", "/srv"]
    );
    assert_eq!(command.cwd.as_deref(), Some("/srv/mcp"));
    assert_eq!(command.pin, ProgramPin::Unpinned);
    assert_eq!(command.idle_s, DEFAULT_IDLE_S);
    let env: BTreeMap<&str, &SecretRef> = command.env.iter().map(|(k, v)| (&**k, v)).collect();
    assert!(matches!(env.get("API_KEY"), Some(SecretRef::Source(_))));
    assert_eq!(env.get("MODE"), Some(&&SecretRef::None));

    let inherit = typed(
        "bare",
        json!({"command": {"argv": ["/bin/srv"], "idle_s": 30}}),
    )
    .expect("cwd is optional");
    let command = inherit.command.expect("command");
    assert!(
        command.cwd.is_none(),
        "no `cwd` inherits busbar's, as 1.5.5 did"
    );
    assert_eq!(command.idle_s, 30);
}

#[test]
fn local_program_needs_its_key_to_be_argv0_and_an_explicit_absolute_cwd() {
    let pinned = typed(
        "local",
        json!({"command": {
            "argv": ["/opt/mcp/files"],
            "cwd": "/srv/mcp",
            "pin": {"mechanism": "local_program", "key": "/opt/mcp/files"},
        }}),
    )
    .expect("a matching local_program pin is accepted");
    assert_eq!(
        pinned.command.expect("command").pin,
        ProgramPin::LocalProgram {
            key: "/opt/mcp/files".into()
        }
    );

    let other_key = refusals(
        "local",
        json!({"command": {
            "argv": ["/opt/mcp/files"],
            "cwd": "/srv/mcp",
            "pin": {"mechanism": "local_program", "key": "/opt/mcp/other"},
        }}),
    );
    assert!(
        other_key.contains("`upstreams.local`") && other_key.contains("equal to the exact"),
        "{other_key}"
    );

    let no_cwd = refusals(
        "local",
        json!({"command": {
            "argv": ["/opt/mcp/files"],
            "pin": {"mechanism": "local_program", "key": "/opt/mcp/files"},
        }}),
    );
    assert!(
        no_cwd.contains("explicit absolute `command.cwd:`"),
        "{no_cwd}"
    );

    let tls_pin = refusals(
        "local",
        json!({"command": {"argv": ["/opt/mcp/files"], "pin": {"mechanism": "cert_spki"}}}),
    );
    assert!(tls_pin.contains("a stdio program has none"), "{tls_pin}");

    let keyed_unpinned = refusals(
        "local",
        json!({"command": {"argv": ["/opt/mcp/files"], "pin": {"mechanism": "unpinned", "key": "/x"}}}),
    );
    assert!(keyed_unpinned.contains("no meaning"), "{keyed_unpinned}");
}

#[test]
fn a_stdio_upstream_refuses_auth_upstream_credentials_and_tls() {
    let entry = json!({"command": {"argv": ["/opt/mcp/files"]}, "auth": {"bearer": "none"}});
    let why = typed_with("files", entry, &bearer())
        .err()
        .expect("auth on stdio is refused")
        .join("\n");
    assert!(
        why.contains("`upstreams.files`")
            && why.contains("`auth:` has no carrier on a stdio upstream"),
        "{why}"
    );

    let creds = UpstreamCfg {
        resource: None,
        auth: None,
        upstream_credentials: Some(UpstreamCreds::Own),
    };
    let why = typed_with(
        "files",
        json!({"command": {"argv": ["/opt/mcp/files"]}, "upstream_credentials": "own"}),
        &creds,
    )
    .err()
    .expect("upstream_credentials on stdio is refused")
    .join("\n");
    assert!(why.contains("`upstream_credentials:`"), "{why}");

    let why = refusals(
        "files",
        json!({"command": {"argv": ["/opt/mcp/files"]}, "tls": {"pin_spki": [PIN_HEX]}}),
    );
    assert!(why.contains("no TLS handshake"), "{why}");
}

#[test]
fn paths_env_names_and_idle_are_held_to_the_launch_rules() {
    for (entry, needle) in [
        (json!({"command": {"argv": ["mcp-files"]}}), "ABSOLUTE path"),
        (
            json!({"command": {"argv": [" /opt/mcp/files"]}}),
            "whitespace",
        ),
        (json!({"command": {"argv": []}}), "must list the program"),
        (json!({"command": {"argv": ["/opt/x\u{0}y"]}}), "NUL"),
        (
            json!({"command": {"argv": ["/opt/x"], "cwd": "srv"}}),
            "ABSOLUTE path",
        ),
        (
            json!({"command": {"argv": ["/opt/x"], "env": {"A=B": "none"}}}),
            "not a usable environment variable name",
        ),
        (
            json!({"command": {"argv": ["/opt/x"], "env": {"KEY": "literal-value"}}}),
            "must be a secret reference",
        ),
        (
            json!({"command": {"argv": ["/opt/x"], "idle_s": 0}}),
            "above 0",
        ),
        (
            json!({"command": {"argv": ["/opt/x"], "shell": true}}),
            "`command.shell` is not an upstream key",
        ),
    ] {
        let why = refusals("x", entry.clone());
        assert!(why.contains(needle), "{entry}: {why}");
    }
    let literal = refusals(
        "x",
        json!({"command": {"argv": ["/opt/x"], "env": {"KEY": "hunter2-literal"}}}),
    );
    assert!(
        !literal.contains("hunter2"),
        "a literal never reaches the refusal: {literal}"
    );
}

#[test]
fn url_and_command_are_exclusive_one_is_required_and_a_url_never_echoes_userinfo() {
    let why = refusals("x", json!({}));
    assert!(why.contains("needs `url:`"), "{why}");
    let why = refusals(
        "x",
        json!({"url": "https://a.example", "command": {"argv": ["/bin/x"]}}),
    );
    assert!(why.contains("two different servers"), "{why}");
    let why = refusals("x", json!({"url": "ftp://a.example/x"}));
    assert!(why.contains("`http://` or `https://`"), "{why}");
    let why = refusals("x", json!({"url": "https://svc:hunter2@a.example/x"}));
    assert!(
        why.contains("userinfo") && !why.contains("hunter2") && !why.contains("svc:"),
        "{why}"
    );
    let why = refusals("x", json!({"url": "https:///x"}));
    assert!(why.contains("names no host"), "{why}");
    let why = refusals("x", json!({"url": "https://a.example", "headers": {}}));
    assert!(why.contains("`headers` is not an upstream key"), "{why}");
    let why = refusals("Bad Name", json!({"url": "https://a.example"}));
    assert!(why.contains("upstream name"), "{why}");
}

#[test]
fn tls_needs_https_and_well_formed_pins_and_trust() {
    let why = refusals(
        "x",
        json!({"url": "http://a.example", "tls": {"pin_spki": [PIN_HEX], "client_identity": secret("/run/id")}}),
    );
    assert!(
        why.contains("`tls.pin_spki` needs a TLS handshake")
            && why.contains("`tls.client_identity` needs a TLS handshake"),
        "{why}"
    );
    let why = refusals(
        "x",
        json!({"url": "https://a.example", "tls": {"pin_spki": ["abcd"]}}),
    );
    assert!(why.contains("`tls.pin_spki[0]`"), "{why}");
    let why = refusals(
        "x",
        json!({"url": "https://a.example", "tls": {"trust": "not pem"}}),
    );
    assert!(why.contains("`tls.trust:` is not a PEM"), "{why}");
    let plain = typed("x", json!({"url": "http://a.example"}))
        .expect("plain http alone is a dial-time question");
    assert!(plain.tls.pin_spki.is_empty());
}

#[test]
fn the_binding_names_the_operator_instance_or_the_implicit_one() {
    let operator = UpstreamAuth::from_config(
        "planner",
        &UpstreamAuthCfg {
            form: UpstreamAuthForm::Instance("corp-oauth".into()),
            cache_max_s: None,
        },
    );
    assert_eq!(
        operator,
        UpstreamAuth {
            instance: "corp-oauth".into(),
            cache_max_s: None,
            connect_callback: None,
            caller: false,
            scoped: false,
            per_request: false,
        }
    );

    let implicit = UpstreamAuth::from_config(
        "planner",
        &UpstreamAuthCfg {
            form: UpstreamAuthForm::Bearer(SecretRef::None),
            cache_max_s: Some(300),
        },
    );
    assert_eq!(&*implicit.instance, "upstream-planner-outbound");
    assert_eq!(implicit.instance, implicit_instance("planner"));
    assert_eq!(implicit.cache_max_s, Some(300));
    assert!(implicit.connect_callback.is_none());

    let connection = |redirect_uri: &str| {
        UpstreamAuth::from_config(
            "docs",
            &UpstreamAuthCfg {
                form: UpstreamAuthForm::Connection {
                    issuer: "https://idp.example".into(),
                    resource: "https://docs.example/mcp".into(),
                    client_id: "busbar".into(),
                    redirect_uri: redirect_uri.into(),
                    authorization_endpoint: "https://idp.example/authorize".into(),
                    token_endpoint: "https://idp.example/token".into(),
                    scopes: None,
                },
                cache_max_s: None,
            },
        )
    };
    let c = connection("https://busbar.example/connect/docs/callback?x=1#f");
    assert_eq!(
        c.connect_callback.as_deref(),
        Some("/connect/docs/callback")
    );
    assert_eq!(&*c.instance, "upstream-docs-outbound");
    assert!(
        !c.caller && !c.scoped && !c.per_request,
        "the style flags are K6's to derive"
    );
    assert_eq!(
        connection("https://busbar.example")
            .connect_callback
            .as_deref(),
        Some("/")
    );

    let def = typed_with(
        "planner",
        json!({"url": "https://a.example", "auth": "x"}),
        &bearer(),
    )
    .expect("a network upstream with a binding is accepted");
    assert_eq!(
        def.auth.map(|a| a.instance),
        Some(implicit_instance("planner"))
    );
}

#[test]
fn the_table_answers_by_name_and_collects_every_refusal() {
    let section = json!({
        "planner": {"url": "https://a.example"},
        "files": {"command": {"argv": ["/opt/mcp/files"]}},
    });
    let section = section.as_object().expect("map");
    let table = ConfiguredUpstreams::from_config(section, &BTreeMap::new(), &anchor)
        .expect("both upstreams are accepted");
    assert_eq!(table.names().collect::<Vec<_>>(), ["files", "planner"]);
    assert_eq!(
        table.get("planner").and_then(|d| d.url.clone()).as_deref(),
        Some("https://a.example")
    );
    assert!(table.get("missing").is_none());
    let shared: Arc<dyn Upstreams> = Arc::new(table);
    assert!(Arc::clone(&shared)
        .get("files")
        .is_some_and(|d| d.command.is_some()));

    let bad = json!({
        "a": {"url": "ftp://a.example"},
        "b": {},
    });
    let mut parsed = BTreeMap::new();
    parsed.insert(Box::<str>::from("ghost"), bearer());
    let why = ConfiguredUpstreams::from_config(bad.as_object().expect("map"), &parsed, &anchor)
        .err()
        .expect("refused");
    assert_eq!(why.len(), 3, "{why:?}");
    assert!(why[0].contains("`upstreams.a`"), "{why:?}");
    assert!(why[1].contains("`upstreams.b`"), "{why:?}");
    assert!(why[2].contains("`upstreams.ghost`"), "{why:?}");
}
