use std::sync::Arc;

use busbar_contract::json::{json, JsonValueTrait, Value};

use super::{core_field_paths, core_secret_paths, declared, Upstreams};

#[test]
fn consumed_core_prefixes_exclude_plugin_lift_authority() {
    let config = json!({"a/b": {"s": {"auth": {"bearer": "literal"}, "custom": "literal"}}});
    let paths = core_field_paths(&config, &["/a~1b/*"]).unwrap();
    assert_eq!(paths.len(), 6);
    for key in [
        "url",
        "command",
        "tls",
        "auth",
        "upstream_credentials",
        "allow_private",
    ] {
        assert!(paths.contains(&format!("/a~1b/s/{key}")));
    }
    assert!(!paths.contains("/a~1b/s/custom"));
    assert!(core_field_paths(&config, &["/a~2b/*"]).is_err());
    assert!(core_field_paths(&json!({"servers": {"s": false}}), &["/servers/*"]).is_err());
    assert!(core_field_paths(&config, &["/missing/*"])
        .unwrap()
        .is_empty());
}
use crate::plugin_config::TrustAnchor;

#[test]
fn binding_resolution_updates_only_the_instances_own_caller_list() {
    use crate::auth_bindings::OperatorAuth;
    let config = json!({"servers": {
        "own": {"url":"https://a.test", "auth":"own-auth"},
        "caller": {"url":"https://b.test", "auth":"caller-auth"}
    }});
    let mut split = declared("p", &config, &["/servers/*"], &anchor).unwrap();
    assert!(split.caller_upstreams().is_empty());
    let operator = [
        OperatorAuth {
            name: "own-auth",
            module: "auth-image",
            style: Some("bearer"),
            settings_keys: Vec::new(),
        },
        OperatorAuth {
            name: "caller-auth",
            module: "auth-image",
            style: Some("oauth-connection"),
            settings_keys: Vec::new(),
        },
    ];
    let implicit = split
        .resolve_bindings(
            &[("auth-image", vec!["bearer", "oauth-connection"])],
            &operator,
            &|_, style| {
                if style == "oauth-connection" {
                    busbar_plugin_abi::auth::STYLE_CALLER
                } else {
                    0
                }
            },
        )
        .unwrap();
    assert!(implicit.is_empty());
    assert_eq!(split.caller_upstreams(), vec![Box::<str>::from("caller")]);
    assert!(
        !split
            .definitions
            .get("own")
            .unwrap()
            .auth
            .as_ref()
            .unwrap()
            .caller
    );
    assert!(
        split
            .definitions
            .get("caller")
            .unwrap()
            .auth
            .as_ref()
            .unwrap()
            .caller
    );
}

fn anchor(_: &str) -> Result<Arc<TrustAnchor>, String> {
    Err("fixture has no trust anchor".into())
}

#[test]
fn selected_resource_is_core_owned_through_split_normalization_and_migration() {
    for resource in [None, Some(Value::from(())), Some(json!("a/b"))] {
        let mut authored = json!({"servers":{"s":{"url":"https://a.test","label":"old"}}});
        if let Some(value) = &resource {
            authored["servers"]["s"]["resource"] = value.clone();
        }
        let split = declared("p", &authored, &["/servers/*"], &anchor).unwrap();
        assert!(split.visible_bag["servers"]["s"].get("resource").is_none());
        let restored = split
            .reattach(&json!({"servers":{"s":{"label":"new"}}}))
            .unwrap();
        assert_eq!(restored["servers"]["s"].get("resource"), resource.as_ref());
        assert!(core_field_paths(&authored, &["/servers/*"])
            .unwrap()
            .contains("/servers/s/resource"));
        assert!(!core_secret_paths(&authored, &["/servers/*"])
            .unwrap()
            .contains("/servers/s/resource"));
        for injected in [Value::from(()), json!("replacement")] {
            assert!(split
                .reattach(&json!({"servers":{"s":{"resource":injected}}}))
                .is_err());
        }
    }
}

#[test]
fn selected_resource_registration_text_is_bounded_before_plane_normalization() {
    for value in [
        json!(""),
        json!("bad\nresource"),
        json!("é".repeat(65)),
        json!("x".repeat(129)),
        json!(1),
        json!({}),
    ] {
        let authored = json!({"servers":{"s":{"url":"https://a.test","resource":value}}});
        assert!(declared("p", &authored, &["/servers/*"], &anchor).is_err());
    }
    let authored = json!({"servers":{"s":{"url":"https://a.test","resource":"é".repeat(64)}}});
    assert!(declared("p", &authored, &["/servers/*"], &anchor).is_ok());
}

#[test]
fn declared_registrations_keep_private_reach_and_auth_isolated() {
    let authored = json!({"servers": {
        "internal": {"url": "https://private.test", "allow_private": true, "label": "inside"},
        "external": {"url": "https://private.test", "label": "outside"}
    }});
    let first = declared("plane-a", &authored, &["/servers/*"], &anchor).unwrap();
    assert!(first.definitions.get("internal").unwrap().allow_private);
    assert!(!first.definitions.get("external").unwrap().allow_private);
    assert_eq!(
        first.visible_bag,
        json!({"servers": {
            "internal": {"label": "inside"}, "external": {"label": "outside"}
        }})
    );
    assert_eq!(
        authored["servers"]["internal"]["allow_private"].as_bool(),
        Some(true)
    );
    assert_eq!(first.origins["internal"], "/servers/internal");
    let other = declared("plane-b", &json!({}), &[], &anchor).unwrap();
    assert!(other.definitions.is_empty());

    let config = json!({"servers": {"c": {"url": "https://private.test", "auth": {"bearer": {"module":"file", "settings":{"path":"/run/token"}}}}}});
    let a = declared("a-b", &config, &["/servers/*"], &anchor).unwrap();
    let b = declared(
        "a",
        &json!({"servers": {"b-c": config["servers"]["c"].clone()}}),
        &["/servers/*"],
        &anchor,
    )
    .unwrap();
    assert_ne!(
        a.definitions
            .get("c")
            .unwrap()
            .auth
            .as_ref()
            .unwrap()
            .instance,
        b.definitions
            .get("b-c")
            .unwrap()
            .auth
            .as_ref()
            .unwrap()
            .instance
    );
}

#[test]
fn declared_private_reach_refuses_non_booleans_and_stdio_presence() {
    for value in [
        Value::from(()),
        json!("true"),
        json!(1),
        json!([]),
        json!({}),
    ] {
        let config =
            json!({"servers": {"s": {"url": "https://private.test", "allow_private": value}}});
        let errors = declared("p", &config, &["/servers/*"], &anchor)
            .err()
            .unwrap();
        assert!(
            errors.iter().any(|e| e.contains("allow_private")),
            "{errors:?}"
        );
    }
    for value in [false, true] {
        let config =
            json!({"servers": {"s": {"command": {"argv": ["/bin/tool"]}, "allow_private": value}}});
        assert!(declared("p", &config, &["/servers/*"], &anchor).is_err());
    }
}

#[test]
fn declared_pointer_shape_and_member_names_are_checked() {
    for (config, paths) in [
        (json!({"servers": null}), vec!["/servers/*"]),
        (json!({"servers": []}), vec!["/servers/*"]),
        (json!({"servers": {"s": false}}), vec!["/servers/*"]),
        (
            json!({"servers": {"bad/name": {"url": "https://x.test"}}}),
            vec!["/servers/*"],
        ),
        (json!({}), vec!["/bad~2/*"]),
        (json!({}), vec!["/servers/*/nested/*"]),
        (json!({}), vec!["/servers/*", "/servers/*"]),
    ] {
        assert!(
            declared("p", &config, &paths, &anchor).is_err(),
            "{paths:?}"
        );
    }
    let duplicate =
        json!({"one": {"s": {"url": "https://a.test"}}, "two": {"s": {"url": "https://b.test"}}});
    assert!(declared("p", &duplicate, &["/one/*", "/two/*"], &anchor).is_err());
    let escaped = json!({"a/b": {"s": {"url": "https://a.test"}}});
    assert_eq!(
        declared("p", &escaped, &["/a~1b/*"], &anchor)
            .unwrap()
            .origins["s"],
        "/a~1b/s"
    );
}

#[test]
fn declared_writeback_restores_core_fields_and_rejects_policy_injection() {
    let authored =
        json!({"servers": {"s": {"url": "https://a.test", "allow_private": true, "label": "old"}}});
    let split = declared("p", &authored, &["/servers/*"], &anchor).unwrap();
    let restored = split
        .reattach(&json!({"servers": {"s": {"label": "new"}}}))
        .unwrap();
    assert_eq!(
        restored,
        json!({"servers": {"s": {"url": "https://a.test", "allow_private": true, "label": "new"}}})
    );
    assert!(split.reattach(&json!({"servers": {}})).is_err());
    assert!(split
        .reattach(&json!({"servers": {"renamed": {}}}))
        .is_err());
    assert!(split
        .reattach(&json!({"servers": {"s": {"allow_private": false}}}))
        .is_err());
    assert!(split
        .reattach(&json!({"servers": {"s": {}, "new": {"url": "https://evil.test"}}}))
        .is_err());
}

#[test]
fn core_lift_paths_are_exact_typed_leaves_of_declared_registrations() {
    let config = json!({"servers": {
        "stdio": {"command": {"argv": ["/bin/tool"], "env": {"A/B": "literal"}}},
        "remote": {"url": "https://x.test", "allow_private": true,
            "tls": {"client_identity": "literal", "trust": "PEM"},
            "auth": {"api_key": {"header": "X-Key", "secret": "literal"}},
            "custom": "literal"}
    }});
    let paths = core_secret_paths(&config, &["/servers/*"]).unwrap();
    assert_eq!(
        paths.into_iter().collect::<Vec<_>>(),
        vec![
            "/servers/remote/auth/api_key/secret",
            "/servers/remote/tls/client_identity",
            "/servers/stdio/command/env/A~1B",
        ]
    );
    assert!(core_secret_paths(
        &json!({"servers": {"s": {"auth": {"unknown": {"secret": "x"}}}}}),
        &["/servers/*"]
    )
    .is_err());
    assert!(core_secret_paths(&json!({"servers": false}), &["/servers/*"]).is_err());
    assert!(core_secret_paths(&config, &["/bad~2/*"]).is_err());
}
