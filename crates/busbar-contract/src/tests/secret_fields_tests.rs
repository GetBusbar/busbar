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
fn resolved_exact_array_secrets_leave_settings_and_lend_in_statement_order() {
    let declared = paths(&["servers.1.token", "servers.0.token"]);
    let mut block = json!({"servers": [
        {"token": {"env": "FIRST"}, "name": "a"},
        {"token": {"env": "SECOND"}, "name": "b"}
    ]});
    crate::secret_fields::resolve_declared(&mut block, &declared, "acme", |field, r| {
        assert!(matches!(field, "servers.1.token" | "servers.0.token"));
        Ok(format!("resolved:{}", r.describe()))
    })
    .expect("declared numeric array paths resolve");
    let first = block["servers"][0]["token"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    let second = block["servers"][1]["token"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    let out = lent(&mut block, &["servers.1.token", "servers.0.token"]);
    assert_eq!(out, vec![second, first]);
    assert_eq!(block, json!({"servers": [{"name": "a"}, {"name": "b"}]}));
}

#[test]
fn exact_array_references_lend_before_resolution_without_remaining_in_settings() {
    let mut block = json!({"servers": [{"token": {"env": "T"}}]});
    assert_eq!(
        crate::secret_fields::declared_references(&block, "servers.0.token"),
        vec![at(&["servers", "0", "token"])]
    );
    assert_eq!(
        lent(&mut block, &["servers.0.token"]),
        vec![b"R:T".to_vec()]
    );
    assert_eq!(block, json!({"servers": [{}]}));
}

#[test]
fn exact_terminal_array_slots_keep_neighboring_indices_and_wildcard_order() {
    let mut block = json!({
        "tokens": ["a", "b", "c", "d"],
        "nested": [[{"env": "N"}]],
        "other": "visible"
    });
    let out = lent(
        &mut block,
        &["tokens.*", "tokens.1", "tokens.3", "nested.0.0", "absent"],
    );
    assert_eq!(
        out,
        vec![
            b"b".to_vec(),
            b"d".to_vec(),
            b"R:N".to_vec(),
            Vec::new(),
            b"a".to_vec(),
            b"c".to_vec()
        ]
    );
    assert_eq!(
        block,
        json!({
            "tokens": [{SECRET_MARKER: 4}, null, {SECRET_MARKER: 5}, null],
            "nested": [[null]],
            "other": "visible"
        })
    );
    let mut root = json!([{"env": "A"}, {"env": "B"}, "visible"]);
    assert_eq!(
        lent(&mut root, &["0", "1"]),
        vec![b"R:A".to_vec(), b"R:B".to_vec()]
    );
    assert_eq!(root, json!([null, null, "visible"]));
}

#[test]
fn exact_numeric_object_keys_remain_keys_when_nested_in_arrays() {
    let mut block = json!({"0": {"01": "a"}, "list": [{"0": "b", "01": "c"}]});
    assert_eq!(
        lent(&mut block, &["0.01", "list.0.01", "list.0.0"]),
        vec![b"a".to_vec(), b"c".to_vec(), b"b".to_vec()]
    );
    assert_eq!(block, json!({"0": {}, "list": [{}]}));
}

#[test]
fn keeping_exact_array_secrets_lends_the_same_positions_without_changing_settings() {
    let original = json!({"list": [{"token": "a"}, "b"]});
    let mut block = original.clone();
    let out = lend(
        &mut block,
        &paths(&["list.1", "list.0.token", "list.2"]),
        true,
        |_, v| {
            Ok::<_, String>(
                v.and_then(|v| v.as_str().map(str::as_bytes).map(Vec::from))
                    .unwrap_or_default(),
            )
        },
        |_, _| -> Result<Vec<u8>, String> { panic!("no wildcard path") },
    )
    .expect("exact fields lend");
    assert_eq!(out, vec![b"b".to_vec(), b"a".to_vec(), Vec::new()]);
    assert_eq!(block, original);
}

#[test]
fn missing_or_invalid_array_paths_lend_unset_without_changing_settings() {
    let original = json!({"list": [{"token": "visible"}], "scalar": 7});
    let mut block = original.clone();
    let out = lend(
        &mut block,
        &paths(&[
            "list.9.token",
            "list.nope",
            "list.184467440737095516160",
            "scalar.0",
            "missing.0",
        ]),
        false,
        |_, value| {
            assert!(value.is_none(), "unset exact path");
            Ok::<_, String>(Vec::<u8>::new())
        },
        |_, _| -> Result<Vec<u8>, String> { panic!("no wildcard path") },
    )
    .expect("unset exact fields lend empty");
    assert!(out.iter().all(Vec::is_empty));
    assert_eq!(block, original);
}

#[test]
fn failing_an_array_secret_lend_wipes_material_already_lent() {
    use std::{cell::RefCell, rc::Rc};
    use zeroize::Zeroize;

    struct Held(Rc<RefCell<Vec<u8>>>);
    impl Zeroize for Held {
        fn zeroize(&mut self) {
            self.0.borrow_mut().as_mut_slice().zeroize();
        }
    }

    let observed = Rc::new(RefCell::new(Vec::new()));
    let mut block = json!({"tokens": ["material", {"invalid": true}], "ordinary": "visible"});
    let material_ptr = block["tokens"][0].as_str().unwrap().as_ptr();
    let result = lend(
        &mut block,
        &paths(&["tokens.0", "tokens.1"]),
        false,
        |path, value| -> Result<Held, &'static str> {
            if path == "tokens.0" {
                let Some(Value::String(material)) = value else {
                    panic!("first array slot lends its material");
                };
                assert_eq!(
                    material.as_ptr(),
                    material_ptr,
                    "the string allocation moves"
                );
                *observed.borrow_mut() = material.into_bytes();
                Ok(Held(observed.clone()))
            } else {
                assert_eq!(value, Some(json!({"invalid": true})));
                Err("invalid reference")
            }
        },
        |_, _| -> Result<Held, &'static str> { panic!("no wildcard path") },
    );
    assert!(matches!(result, Err("invalid reference")));
    assert_eq!(*observed.borrow(), vec![0; b"material".len()]);
    assert_eq!(
        block,
        json!({"tokens": [null, null], "ordinary": "visible"})
    );
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
