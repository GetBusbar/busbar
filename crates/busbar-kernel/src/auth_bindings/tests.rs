// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::config::UpstreamCreds;
use busbar_plugin_abi::auth::{STYLE_CALLER, STYLE_SCOPE};

use super::*;
use crate::config::min3::{UpstreamAuthCfg, UpstreamAuthForm};

fn header_row(dialect: &str, key_header: Option<&str>) -> DialectAuthOwned {
    DialectAuthOwned {
        dialect: dialect.into(),
        present: PresentationOwned::Header {
            key_header: key_header.map(Box::from),
            own_header: None,
            passthrough_header: None,
            families: Vec::new(),
        },
    }
}

fn provider<'a>(name: &'a str, protocol: &'a str) -> ProviderView<'a> {
    ProviderView {
        name,
        protocol,
        base_url: None,
        auth: ProviderAuth::None,
        has_api_key: true,
        token_url: None,
        scope: None,
        subject: None,
    }
}

fn member<'a>(plane: &'a str, provider: &'a str) -> MemberView<'a> {
    MemberView {
        member: "m",
        plane,
        image: "llm",
        provider,
        dialect: None,
    }
}

fn rows() -> Vec<(&'static str, Vec<DialectAuthOwned>)> {
    vec![(
        "llm",
        vec![
            header_row("openai", None),
            header_row("anthropic", Some("x-api-key")),
        ],
    )]
}

fn styles() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("hdr", vec!["bearer", "api-key"]),
        // auth-oauth declares `oauth-token-exchange` too (busbar_contract::config::dialect_styles::TOKEN_EXCHANGE);
        // 7247f5d1f1 binds an operator instance of it.
        ("oauth", vec!["oauth-connection", "oauth-token-exchange"]),
    ]
}

fn plan<'a>(
    members: &'a [MemberView<'a>],
    providers: &'a [ProviderView<'a>],
    rows: &'a [(&'a str, Vec<DialectAuthOwned>)],
    styles: &'a [(&'a str, Vec<&'a str>)],
    operator: &'a [OperatorAuth<'a>],
) -> ProviderPlan<'a> {
    ProviderPlan {
        members,
        providers,
        rows,
        styles,
        operator,
    }
}

/// Guards C-DIALECT-AUTH (b): two providers of two protocols open two implicit instances, one per
/// dialect, each with its own style (a model reaches a second protocol through a second `providers:` entry).
#[test]
fn two_providers_of_two_dialects_get_two_implicit_bindings() {
    let providers = [provider("p", "openai"), provider("q", "anthropic")];
    let members = [member("llm1", "p"), member("llm1", "q")];
    let (rows, styles) = (rows(), styles());
    let got = bind_providers(&plan(&members, &providers, &rows, &styles, &[])).unwrap();
    let mut names: Vec<_> = got.implicit.iter().map(|i| (&*i.name, &*i.style)).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            ("p-openai-outbound", "bearer"),
            ("q-anthropic-outbound", "api-key")
        ]
    );
}

/// Guards dedup by value (C-DIALECT-AUTH (i)): two plane instances of one image share one instance.
#[test]
fn two_planes_with_equal_rows_share_one_implicit_binding() {
    let providers = [provider("p", "openai")];
    let members = [member("llm1", "p"), member("llm2", "p")];
    let (rows, styles) = (rows(), styles());
    let got = bind_providers(&plan(&members, &providers, &rows, &styles, &[])).unwrap();
    assert_eq!(got.implicit.len(), 1);
    assert_eq!(&*got.implicit[0].name, "p-openai-outbound");
    assert_eq!(got.by_attempt.len(), 2);
}

/// Guards the `<p>-<d>-<v>-outbound` naming when planes of different images give one (p, d) two bindings.
#[test]
fn differing_rows_for_one_provider_dialect_name_by_the_first_plane() {
    let providers = [provider("p", "openai")];
    let a = member("llm1", "p");
    let b = MemberView {
        image: "stream",
        plane: "st1",
        ..member("llm1", "p")
    };
    let mut rows = rows();
    rows.push(("stream", vec![header_row("openai", Some("x-goog-api-key"))]));
    let styles = styles();
    let members = [a, b];
    let got = bind_providers(&plan(&members, &providers, &rows, &styles, &[])).unwrap();
    let mut names: Vec<_> = got.implicit.iter().map(|i| i.name.to_string()).collect();
    names.sort_unstable();
    assert_eq!(names, ["p-openai-llm1-outbound", "p-openai-st1-outbound"]);
}

/// Guards the no-row refusal text.
#[test]
fn no_row_for_a_keyed_provider_refuses_with_todays_text() {
    let providers = [provider("p", "cohere")];
    let members = [member("llm1", "p")];
    let (rows, styles) = (rows(), styles());
    let err = bind_providers(&plan(&members, &providers, &rows, &styles, &[]))
        .err()
        .unwrap();
    assert_eq!(
        err,
        ["member 'm': provider 'p' states no `auth:` and its plane declares no default style for the dialect 'cohere'"]
    );
}

/// Guards the squat refusal: an operator instance under an implicit name.
#[test]
fn an_operator_instance_under_an_implicit_name_refuses() {
    let providers = [provider("p", "openai")];
    let members = [member("llm1", "p")];
    let (rows, styles) = (rows(), styles());
    let op = [OperatorAuth {
        name: "p-openai-outbound",
        module: "hdr",
        style: Some("bearer"),
        settings_keys: Vec::new(),
    }];
    let err = bind_providers(&plan(&members, &providers, &rows, &styles, &op))
        .err()
        .unwrap();
    assert_eq!(
        err,
        ["`auth.p-openai-outbound` is the name core gives an implicit outbound binding; name it in `providers.p.auth`"]
    );
}

/// Guards the explicit-binding fill: an operator binding of the row's style gets core's absent keys.
#[test]
fn an_explicit_binding_of_the_rows_style_gets_the_absent_core_keys() {
    let mut p = provider("p", "openai");
    p.auth = ProviderAuth::Instance("mine");
    let providers = [p];
    let members = [member("llm1", "p")];
    let (rows, styles) = (rows(), styles());
    let op = [OperatorAuth {
        name: "mine",
        module: "hdr",
        style: Some("bearer"),
        settings_keys: vec!["own"],
    }];
    let got = bind_providers(&plan(&members, &providers, &rows, &styles, &op)).unwrap();
    let keys: Vec<_> = got.fills["mine"].iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, ["passthrough", "families", "protocol"]);
}

/// Guards the operator style check: a style its module does not declare refuses.
#[test]
fn an_operator_style_its_module_does_not_declare_refuses() {
    let op = [OperatorAuth {
        name: "mine",
        module: "hdr",
        style: Some("sigv4"),
        settings_keys: Vec::new(),
    }];
    let (rows, styles) = (rows(), styles());
    let err = bind_providers(&plan(&[], &[], &rows, &styles, &op))
        .err()
        .unwrap();
    assert_eq!(
        err,
        ["`auth.mine`: its module declares no outbound style `sigv4`"]
    );
}

fn connection_form() -> UpstreamAuthCfg {
    UpstreamAuthCfg {
        form: UpstreamAuthForm::Connection {
            issuer: "https://idp".into(),
            resource: "https://mcp".into(),
            client_id: "c".into(),
            redirect_uri: "https://gw.example.com/connect/cb?x=1".into(),
            authorization_endpoint: "https://idp/a".into(),
            token_endpoint: "https://idp/t".into(),
            scopes: None,
        },
        cache_max_s: Some(300),
    }
}

fn flags(module: &str, style: &str) -> u64 {
    match (module, style) {
        ("oauth", "oauth-connection") => STYLE_CALLER,
        ("oauth", "oauth-token-exchange") => STYLE_SCOPE,
        _ => 0,
    }
}

/// Guards C-UPSTREAM-AUTH's derivation: a `connection` form is caller-mode, opens `upstream-<n>-outbound` and
/// carries the callback path of its `redirect_uri`.
#[test]
fn a_connection_form_binds_caller_mode_with_its_callback_path() {
    let cfg = connection_form();
    let views = [UpstreamView {
        name: "gh",
        auth: Some(&cfg),
        upstream_credentials: None,
        stdio: false,
    }];
    let got = bind_upstreams(&views, &styles(), &[], &flags).unwrap();
    let auth = got[0].auth.clone().unwrap();
    assert_eq!(&*auth.instance, "upstream-gh-outbound");
    assert!(auth.caller && !auth.scoped && !auth.per_request);
    assert_eq!(auth.cache_max_s, Some(300));
    assert_eq!(auth.connect_callback.as_deref(), Some("/connect/cb"));
    assert_eq!(&*got[0].implicit.as_ref().unwrap().module, "oauth");
}

/// Guards the stdio refusal and the squat refusal for upstream forms.
#[test]
fn a_form_on_stdio_and_an_operator_squat_refuse() {
    let cfg = connection_form();
    let stdio = [UpstreamView {
        name: "s",
        auth: Some(&cfg),
        upstream_credentials: None,
        stdio: true,
    }];
    assert_eq!(
        bind_upstreams(&stdio, &styles(), &[], &flags)
            .err()
            .unwrap(),
        ["`upstreams.s.auth` has no carrier on `transport: stdio`"]
    );
    let squat = [OperatorAuth {
        name: "upstream-s-outbound",
        module: "oauth",
        style: None,
        settings_keys: Vec::new(),
    }];
    let http = [UpstreamView {
        stdio: false,
        ..stdio.into_iter().next().unwrap()
    }];
    assert_eq!(
        bind_upstreams(&http, &styles(), &squat, &flags).err().unwrap(),
        ["`auth.upstream-s-outbound` is the name core gives an implicit outbound binding; name it in `upstreams.s.auth`"]
    );
}

/// Guards the operator form: it names a configured instance whose style flags decide the mode.
#[test]
fn the_operator_form_reads_its_instances_style_flags() {
    let cfg = UpstreamAuthCfg {
        form: UpstreamAuthForm::Instance("x".into()),
        cache_max_s: None,
    };
    let view = [UpstreamView {
        name: "u",
        auth: Some(&cfg),
        upstream_credentials: None,
        stdio: false,
    }];
    let op = [OperatorAuth {
        name: "x",
        module: "oauth",
        style: Some("oauth-connection"),
        settings_keys: Vec::new(),
    }];
    let got = bind_upstreams(&view, &styles(), &op, &flags).unwrap();
    assert!(got[0].implicit.is_none());
    assert!(got[0].auth.as_ref().unwrap().caller);
    assert!(bind_upstreams(&view, &styles(), &[], &flags).is_err());
}

/// Guards the three `upstream_credentials` refusals (IF §12.18 round 22) and the agreeing cases.
#[test]
fn upstream_credentials_must_agree_with_the_binding() {
    use UpstreamCreds::{Connection, Own, Passthrough};
    let ok = check_upstream_credentials;
    assert!(ok("u", Some(Connection), None, false)
        .unwrap_err()
        .contains("is `connection`, but its `auth` presents its own credential"));
    assert!(ok("u", Some(Connection), Some(false), true).is_err());
    assert!(ok("u", Some(Own), Some(true), true)
        .unwrap_err()
        .contains("is a per-caller connection"));
    assert!(ok("u", Some(Passthrough), Some(false), true).is_err());
    assert_eq!(ok("u", Some(Passthrough), Some(false), false), Ok(()));
    assert_eq!(ok("u", Some(Connection), Some(true), true), Ok(()));
    assert_eq!(ok("u", None, Some(true), true), Ok(()));
    assert_eq!(ok("u", Some(Own), None, false), Ok(()));
}

#[test]
fn scoped_upstream_bindings_use_collision_free_reserved_identity() {
    let cfg = connection_form();
    let resolve = |instance: &str, name: &str| {
        bind_upstreams_for(
            instance,
            &[UpstreamView {
                name,
                auth: Some(&cfg),
                upstream_credentials: Some(UpstreamCreds::Connection),
                stdio: false,
            }],
            &styles(),
            &[],
            &flags,
        )
        .unwrap()
    };
    let left = resolve("a-b", "c");
    let right = resolve("a", "b-c");
    let left = left[0].auth.as_ref().unwrap();
    let right = right[0].auth.as_ref().unwrap();
    assert_ne!(left.instance, right.instance);
    assert_eq!(&*left.instance, "\0upstream:3:a-b1:c");
    assert_eq!(&*right.instance, "\0upstream:1:a3:b-c");
    assert!(left.caller && right.caller);
    assert_eq!(left.connect_callback.as_deref(), Some("/connect/cb"));
}

#[test]
fn scoped_bindings_preserve_explicit_own_bindings_and_do_not_reserve_legacy_names() {
    let form = connection_form();
    let explicit = UpstreamAuthCfg {
        form: UpstreamAuthForm::Instance("upstream-c-outbound".into()),
        cache_max_s: Some(17),
    };
    let op = [OperatorAuth {
        name: "upstream-c-outbound",
        module: "oauth",
        style: Some("oauth-token-exchange"),
        settings_keys: Vec::new(),
    }];
    let views = [
        UpstreamView {
            name: "c",
            auth: Some(&form),
            upstream_credentials: Some(UpstreamCreds::Connection),
            stdio: false,
        },
        UpstreamView {
            name: "explicit",
            auth: Some(&explicit),
            upstream_credentials: Some(UpstreamCreds::Own),
            stdio: false,
        },
    ];
    let mask = |module: &str, style: &str| {
        flags(module, style) | busbar_plugin_abi::auth::STYLE_PER_REQUEST
    };
    let got = bind_upstreams_for("plane", &views, &styles(), &op, &mask).unwrap();
    assert!(got[0].implicit.is_some());
    let own = got[1].auth.as_ref().unwrap();
    assert!(got[1].implicit.is_none());
    assert_eq!(&*own.instance, "upstream-c-outbound");
    assert!(!own.caller && own.scoped && own.per_request);
    assert_eq!(own.cache_max_s, Some(17));
}

#[test]
fn scoped_bindings_refuse_operator_names_in_the_internal_namespace() {
    let operator = [OperatorAuth {
        name: "\0upstream:1:a1:b",
        module: "oauth",
        style: Some("oauth-connection"),
        settings_keys: Vec::new(),
    }];
    let refused = bind_upstreams_for("plane", &[], &styles(), &operator, &flags)
        .err()
        .expect("reserved operator name");
    assert!(refused.iter().any(|message| message.contains("reserved")));
    assert!(refused.iter().all(|message| !message.contains('\0')));
}

#[test]
fn scoped_bindings_keep_credential_mode_and_stdio_refusals() {
    let cfg = connection_form();
    let own = [UpstreamView {
        name: "c",
        auth: Some(&cfg),
        upstream_credentials: Some(UpstreamCreds::Own),
        stdio: false,
    }];
    assert!(bind_upstreams_for("plane", &own, &styles(), &[], &flags).is_err());
    let stdio = [UpstreamView {
        name: "c",
        auth: Some(&cfg),
        upstream_credentials: None,
        stdio: true,
    }];
    assert!(bind_upstreams_for("plane", &stdio, &styles(), &[], &flags).is_err());
}

#[test]
fn configured_member_dialect_selects_its_own_image_local_auth_row() {
    let providers = [provider("p", "openai")];
    let members = [
        member("llm1", "p"),
        MemberView {
            dialect: Some("anthropic"),
            ..member("llm1", "p")
        },
    ];
    let (rows, styles) = (rows(), styles());
    let got = bind_providers(&plan(&members, &providers, &rows, &styles, &[])).unwrap();
    assert_eq!(got.by_attempt.len(), 2);
    assert_eq!(
        got.by_attempt
            .get(&("llm1".into(), "p".into(), "anthropic".into()))
            .map(AsRef::as_ref),
        Some("p-anthropic-outbound")
    );
    assert!(got
        .implicit
        .iter()
        .any(|instance| instance.name.as_ref() == "p-anthropic-outbound"
            && instance.style.as_ref() == "api-key"));
}
