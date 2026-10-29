// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_json::{json, Value};

use crate::secret_fields::{covers, lend, undeclared_reference, undeclared_refusal, SECRET_MARKER};

fn paths(p: &[&str]) -> Vec<String> {
    p.iter().map(|s| (*s).to_string()).collect()
}

fn at(p: &[&str]) -> Vec<String> {
    paths(p)
}

/// The lend every host runs with a resolver standing in: a reference lends `R:<env>`, a string
/// lends its bytes.
fn lent(block: &mut Value, declared: &[&str]) -> Vec<Vec<u8>> {
    let resolve = |v: Value| -> Result<Vec<u8>, String> {
        match v {
            Value::String(s) => Ok(s.into_bytes()),
            Value::Object(o) => Ok(format!(
                "R:{}",
                o.get("env").and_then(Value::as_str).unwrap_or("?")
            )
            .into_bytes()),
            _ => Err("neither".into()),
        }
    };
    lend(
        block,
        &paths(declared),
        false,
        |_, v| v.map_or(Ok(Vec::new()), resolve),
        |_, v| resolve(v),
    )
    .expect("lends")
}

#[test]
fn a_star_matches_any_key_and_any_index() {
    assert!(covers(
        "servers.*.env.*",
        &at(&["servers", "a", "env", "K"])
    ));
    assert!(covers("hosts.*.password", &at(&["hosts", "0", "password"])));
    assert!(covers("client_secret", &at(&["client_secret"])));
    assert!(!covers("servers.*.env.*", &at(&["servers", "a", "env"])));
    assert!(!covers("servers.*.env", &at(&["servers", "a", "env", "K"])));
    assert!(!covers("client_secret", &at(&["client_id"])));
}

#[test]
fn exact_paths_lend_in_order_and_are_taken_out_as_today() {
    let mut block =
        json!({"client_secret": {"env": "S"}, "nested": {"key": {"env": "K"}}, "id": "x"});
    let out = lent(&mut block, &["client_secret", "nested.key", "absent"]);
    assert_eq!(out, vec![b"R:S".to_vec(), b"R:K".to_vec(), Vec::new()]);
    assert_eq!(block, json!({"nested": {}, "id": "x"}));
}

#[test]
fn wildcard_matches_lend_after_the_exact_ones_in_document_order_behind_markers() {
    let mut block = json!({
        "token": {"env": "T"},
        "servers": {
            "a": {"command": "run", "env": {"API_KEY": {"env": "A"}, "LOG": "debug"}},
            "b": {"env": {"OTHER": {"file": "/run/k"}}}
        },
        "list": [{"password": "p0"}, {"password": 7}]
    });
    let out = lent(&mut block, &["servers.*.env.*", "token", "list.*.password"]);
    assert_eq!(
        out,
        vec![
            b"R:T".to_vec(),
            b"R:A".to_vec(),
            b"debug".to_vec(),
            b"R:?".to_vec(),
            b"p0".to_vec()
        ]
    );
    assert_eq!(
        block,
        json!({
            "servers": {
                "a": {"command": "run", "env": {"API_KEY": {SECRET_MARKER: 1}, "LOG": {SECRET_MARKER: 2}}},
                "b": {"env": {"OTHER": {SECRET_MARKER: 3}}}
            },
            "list": [{"password": {SECRET_MARKER: 4}}, {"password": 7}]
        })
    );
}

#[test]
fn a_reference_at_an_undeclared_position_is_found_anywhere() {
    let declared = paths(&["client_secret", "servers.*.env.*"]);
    let ok = json!({
        "client_secret": {"env": "S"},
        "servers": {"a": {"env": {"K": {"file": "/k"}}}},
        "plain": {"env_name": "x"},
        "data": {"literal": {"env": "HOME"}}
    });
    assert_eq!(undeclared_reference(&ok, &declared), None);
    let top = json!({"api_base": {"env": "GHE_API"}});
    assert_eq!(
        undeclared_reference(&top, &declared).as_deref(),
        Some("api_base")
    );
    let deep = json!({"servers": {"a": {"headers": [{"v": {"module": "vault", "settings": {}}}]}}});
    assert_eq!(
        undeclared_reference(&deep, &declared).as_deref(),
        Some("servers.a.headers.0.v")
    );
    let under_wild_parent = json!({"servers": {"a": {"env": {"env": "X"}}}});
    assert_eq!(
        undeclared_reference(&under_wild_parent, &declared).as_deref(),
        Some("servers.a.env")
    );
}

#[test]
fn the_refusal_names_the_field_the_plugin_and_the_way_out() {
    let s = undeclared_refusal("store.settings.dsn", "busbar-store-postgres");
    assert!(s.contains("store.settings.dsn"), "{s}");
    assert!(s.contains("busbar-store-postgres"), "{s}");
    assert!(s.contains("did not declare"), "{s}");
    assert!(s.contains("write the value itself"), "{s}");
}

#[test]
fn the_secret_kinds_host_keeps_the_exact_values_in_the_settings() {
    let mut block = json!({"token": {"env": "T"}, "extra": {"a": "x"}});
    let out = lend(
        &mut block,
        &paths(&["token", "extra.*"]),
        true,
        |_, v| {
            Ok::<_, String>(if v.is_some() {
                b"t".to_vec()
            } else {
                Vec::new()
            })
        },
        |_, v| Ok(v.as_str().unwrap_or_default().as_bytes().to_vec()),
    )
    .expect("lends");
    assert_eq!(out, vec![b"t".to_vec(), b"x".to_vec()]);
    assert_eq!(
        block,
        json!({"token": {"env": "T"}, "extra": {"a": {SECRET_MARKER: 1}}})
    );
}

#[test]
fn declared_references_are_the_references_a_path_names() {
    let v = json!({"s": {"a": {"k": {"env": "A"}, "j": "lit"}, "b": [{"env": "B"}]}});
    assert_eq!(
        crate::secret_fields::declared_references(&v, "s.*.*"),
        vec![at(&["s", "a", "k"]), at(&["s", "b", "0"])]
    );
}

#[test]
fn resolve_declared_resolves_declared_references_in_place_and_refuses_the_rest() {
    let resolve = |_: &str, r: &crate::secret_ref::SecretRef| Ok(format!("R:{}", r.describe()));
    let mut ok =
        json!({"dsn": {"env": "PG"}, "servers": {"a": {"env": {"K": {"env": "K"}}, "cmd": "lit"}}});
    crate::secret_fields::resolve_declared(
        &mut ok,
        &paths(&["dsn", "servers.*.env.*"]),
        "p",
        resolve,
    )
    .expect("declared");
    assert!(
        ok["dsn"].as_str().is_some_and(|s| s.starts_with("R:")),
        "{ok}"
    );
    assert!(
        ok["servers"]["a"]["env"]["K"]
            .as_str()
            .is_some_and(|s| s.starts_with("R:")),
        "{ok}"
    );
    assert_eq!(ok["servers"]["a"]["cmd"], json!("lit"));
    let mut bad = json!({"base": {"env": "B"}});
    let e = crate::secret_fields::resolve_declared(&mut bad, &paths(&["dsn"]), "acme", resolve)
        .expect_err("undeclared");
    assert!(e.contains("settings.base") && e.contains("'acme'"), "{e}");
}

/// As the kernel resolves (lead ruling item 7b): a literal at a declared path is refused, at an
/// EXACT path and at a WILDCARD path alike, naming the position and the plugin and never the value.
/// An unset (`null`) declared position is not a literal.
#[test]
fn resolve_declared_refuses_a_literal_at_an_exact_or_a_wildcard_declared_path() {
    let resolve = |_: &str, r: &crate::secret_ref::SecretRef| Ok(format!("R:{}", r.describe()));
    for (mut tree, at) in [
        (
            json!({"dsn": "postgres://u:pasted-7b@db/x"}),
            "settings.dsn",
        ),
        (
            json!({"servers": {"a": {"env": {"K": "pasted-7b"}}}}),
            "settings.servers.a.env.K",
        ),
        (
            json!({"servers": {"a": {"env": {"K": {"literal": "pasted-7b"}}}}}),
            "settings.servers.a.env.K",
        ),
    ] {
        let Err(e) = crate::secret_fields::resolve_declared(
            &mut tree,
            &paths(&["dsn", "servers.*.env.*"]),
            "acme",
            resolve,
        ) else {
            panic!("a literal at {at} refuses");
        };
        assert!(
            e.starts_with(&format!("{at}: ")) && e.contains("'acme'"),
            "{e}"
        );
        assert!(
            e.contains("a secret value must be a REFERENCE, never an inline literal"),
            "{e}"
        );
        assert!(!e.contains("pasted-7b"), "the value is echoed: {e}");
    }
    let mut unset = json!({"dsn": null, "servers": {"a": {"env": {"K": null}}}});
    crate::secret_fields::resolve_declared(
        &mut unset,
        &paths(&["dsn", "servers.*.env.*"]),
        "acme",
        resolve,
    )
    .expect("an unset declared position is not a literal");
}

/// REFERENCE-CAPABLE, NOT-SECRET FIELDS (lead ruling item 7a): at a path the plugin names in its
/// Statement's reference-capable list, a reference resolves IN PLACE to its string (a 1.5.5 store,
/// exporter or hook `url: {env: VAR}`), a literal passes as written (the 1.5.5 literal url), and a
/// reference anywhere else is still refused. Exact and `*` paths alike.
#[test]
fn a_reference_capable_field_resolves_a_reference_and_passes_a_literal() {
    let resolve = |_: &str, r: &crate::secret_ref::SecretRef| Ok(format!("R:{}", r.describe()));
    let mut by_ref = json!({"url": {"env": "OTLP_URL"}, "sinks": [{"to": {"env": "TO"}}]});
    crate::secret_fields::resolve_declared_fields(
        &mut by_ref,
        &paths(&["auth_header.value"]),
        &paths(&["url", "sinks.*.to"]),
        "acme",
        resolve,
    )
    .expect("a reference at a reference-capable field resolves");
    assert!(
        by_ref["url"].as_str().is_some_and(|s| s.starts_with("R:")),
        "{by_ref}"
    );
    assert!(
        by_ref["sinks"][0]["to"]
            .as_str()
            .is_some_and(|s| s.starts_with("R:")),
        "{by_ref}"
    );

    let literal = json!({"url": "https://collector.example/v1/traces", "sinks": [{"to": "x"}]});
    let mut as_written = literal.clone();
    crate::secret_fields::resolve_declared_fields(
        &mut as_written,
        &paths(&["auth_header.value"]),
        &paths(&["url", "sinks.*.to"]),
        "acme",
        resolve,
    )
    .expect("a literal at a reference-capable field is not refused");
    assert_eq!(as_written, literal, "a literal passes as written");

    let mut elsewhere = json!({"url": "https://x", "batch": {"env": "B"}});
    let e = crate::secret_fields::resolve_declared_fields(
        &mut elsewhere,
        &[],
        &paths(&["url"]),
        "acme",
        resolve,
    )
    .expect_err("a reference outside both lists is still refused");
    assert!(e.contains("settings.batch") && e.contains("'acme'"), "{e}");
}

/// A reference-capable field is NEVER a secret: it is never lent (no `{"$secret": …}` marker, no
/// secret blob) and a declared SECRET path beside it still refuses its literal.
#[test]
fn a_reference_capable_field_is_never_lent_and_a_secret_beside_it_still_refuses_a_literal() {
    let resolve = |_: &str, r: &crate::secret_ref::SecretRef| Ok(format!("R:{}", r.describe()));
    let mut tree = json!({"url": "https://x", "auth_header": {"value": "pasted-7a"}});
    let e = crate::secret_fields::resolve_declared_fields(
        &mut tree,
        &paths(&["auth_header.value"]),
        &paths(&["url"]),
        "acme",
        resolve,
    )
    .expect_err("the secret literal refuses");
    assert!(e.starts_with("settings.auth_header.value: "), "{e}");
    assert!(!e.contains("pasted-7a"), "{e}");

    // The lend reads the SECRET list only: a reference-capable path's value stays in the settings.
    let mut block = json!({"url": "https://x", "auth_header": {"value": "s"}});
    let lent = lent(&mut block, &["auth_header.value"]);
    assert_eq!(lent, vec![b"s".to_vec()]);
    assert_eq!(block["url"], json!("https://x"));
}

/// A PATH IN BOTH LISTS is a contradiction (refused at load): it names the path and the plugin.
#[test]
fn a_path_in_both_lists_is_a_contradiction() {
    assert_eq!(
        crate::secret_fields::contradiction(&paths(&["token", "url"]), &paths(&["base", "url"])),
        Some("url".to_string())
    );
    assert_eq!(
        crate::secret_fields::contradiction(&paths(&["token"]), &paths(&["url"])),
        None
    );
    let e = crate::secret_fields::contradiction_refusal("url", "acme");
    assert!(e.contains("url") && e.contains("'acme'"), "{e}");
    let resolve = |_: &str, r: &crate::secret_ref::SecretRef| Ok(format!("R:{}", r.describe()));
    let mut tree = json!({"url": {"env": "U"}});
    let e = crate::secret_fields::resolve_declared_fields(
        &mut tree,
        &paths(&["url"]),
        &paths(&["url"]),
        "acme",
        resolve,
    )
    .expect_err("a contradicting Statement resolves nothing");
    assert!(e.contains("url") && e.contains("'acme'"), "{e}");
    assert_eq!(tree, json!({"url": {"env": "U"}}));
}
