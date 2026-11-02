// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn declared(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|p| (*p).to_string()).collect()
}

fn obj(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
fn resolves_secret_ref_settings_and_passes_plain_through() {
    let var = format!("BUSBAR_PLUGIN_LICENSE_TEST_{}", std::process::id());
    std::env::set_var(&var, "LIC-123\n");
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[
        ("licenseKey", serde_json::json!({ "env": var })),
        ("endpoint", serde_json::json!("https://example.test")),
        ("retries", serde_json::json!(3)),
    ]);
    let out = resolve_settings(
        &settings,
        &declared(&["licenseKey"]),
        &[],
        "test-plugin",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .unwrap();

    assert_eq!(
        out.get("licenseKey").unwrap(),
        &serde_json::json!("LIC-123")
    );

    assert_eq!(
        out.get("endpoint").unwrap(),
        &serde_json::json!("https://example.test")
    );
    assert_eq!(out.get("retries").unwrap(), &serde_json::json!(3));
    std::env::remove_var(&var);
}

#[test]
fn leaves_non_ref_object_settings_untouched() {
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[("db", serde_json::json!({ "path": ":memory:", "wal": true }))]);
    let out = resolve_settings(
        &settings,
        &declared(&[]),
        &[],
        "test-plugin",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .unwrap();
    assert_eq!(
        out.get("db").unwrap(),
        &serde_json::json!({ "path": ":memory:", "wal": true })
    );
}

#[test]
fn unresolvable_secret_ref_setting_fails_closed_naming_field() {
    let var = format!("BUSBAR_PLUGIN_LICENSE_MISSING_{}", std::process::id());
    std::env::remove_var(&var);
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[("license", serde_json::json!({ "env": var }))]);
    let err = resolve_settings(
        &settings,
        &declared(&["license"]),
        &[],
        "test-plugin",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .unwrap_err();
    assert!(err.contains("license"), "names the field: {err}");
    assert!(err.contains("did not resolve"), "fail-closed: {err}");
}

#[test]
fn unknown_secret_module_in_setting_fails_closed() {
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[(
        "licenseKey",
        serde_json::json!({ "module": "vault", "settings": { "path": "kv/license" } }),
    )]);
    let err = resolve_settings(
        &settings,
        &declared(&["licenseKey"]),
        &[],
        "test-plugin",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .unwrap_err();
    assert!(
        err.contains("licenseKey") && err.contains("fail-closed"),
        "unknown module fails closed: {err}"
    );
}

#[test]
fn literal_wrapper_opts_a_setting_out_of_secret_coercion() {
    let path = std::env::temp_dir().join(format!("busbar-lit-{}.txt", std::process::id()));
    std::fs::write(&path, b"THE-SECRET").unwrap();
    let resolver = SecretResolver::builtins_only();

    let mut settings = serde_json::Map::new();
    settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "file": path.to_string_lossy() }),
    );
    let out = resolve_settings(
        &settings,
        &declared(&["licenseKey"]),
        &[],
        "test-plugin",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("resolves");
    assert_eq!(out["licenseKey"], serde_json::json!("THE-SECRET"));

    let mut settings = serde_json::Map::new();
    settings.insert(
        "db".to_string(),
        serde_json::json!({ "literal": { "file": path.to_string_lossy() } }),
    );
    let out = resolve_settings(
        &settings,
        &declared(&[]),
        &[],
        "test-plugin",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("resolves");
    assert_eq!(
        out["db"],
        serde_json::json!({ "file": path.to_string_lossy() }),
        "a `literal:`-wrapped object is passed through untouched, never dereferenced"
    );

    let mut settings = serde_json::Map::new();
    settings.insert("n".to_string(), serde_json::json!({ "literal": 42 }));
    settings.insert("plain".to_string(), serde_json::json!({ "db_path": "x" }));
    let out = resolve_settings(
        &settings,
        &declared(&[]),
        &[],
        "test-plugin",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("resolves");
    assert_eq!(out["n"], serde_json::json!(42));
    assert_eq!(out["plain"], serde_json::json!({ "db_path": "x" }));

    let _ = std::fs::remove_file(&path);
}

struct ConfigTimeOnly;

impl busbar_contract::secret::SecretResolve for ConfigTimeOnly {
    fn resolve(
        &self,
        _secret: &SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        Err("refused off config time".to_string())
    }

    fn resolve_string(
        &self,
        _secret: &SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        Err("refused off config time".to_string())
    }

    fn resolve_at_config(
        &self,
        _secret: &SecretRef,
        _scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        Ok(busbar_contract::redacted::Secret::new(
            b"AT-CONFIG".to_vec(),
        ))
    }

    fn resolve_string_at_config(
        &self,
        _secret: &SecretRef,
        _scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        Ok(busbar_contract::redacted::Secret::new(
            "AT-CONFIG".to_string(),
        ))
    }
}

#[test]
fn settings_resolve_through_the_config_time_form_with_the_proof() {
    let settings = obj(&[(
        "licenseKey",
        serde_json::json!({ (busbar_contract::secret_ref::SECRET_MODULE_ENV): "UNUSED" }),
    )]);
    let out = resolve_settings(
        &settings,
        &declared(&["licenseKey"]),
        &[],
        "test-plugin",
        &ConfigTimeOnly,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("a config-time resolution answers");
    assert_eq!(out["licenseKey"], serde_json::json!("AT-CONFIG"));
}

#[test]
fn the_kernel_resolver_answers_the_same_at_config_time_for_a_built_in() {
    let var = format!("BUSBAR_CONFIG_TIME_SAME_{}", std::process::id());
    std::env::set_var(&var, "SAME\n");
    let reference: SecretRef = serde_json::from_value(
        serde_json::json!({ (busbar_contract::secret_ref::SECRET_MODULE_ENV): var }),
    )
    .expect("an env reference");
    let resolver = SecretResolver::builtins_only();
    let scope = busbar_contract::config_time::ConfigScope::config_time();
    let dynamic: &dyn busbar_contract::secret::SecretResolve = &resolver;
    assert_eq!(
        dynamic.resolve_string_at_config(&reference, &scope),
        dynamic.resolve_string(&reference)
    );
    assert_eq!(
        dynamic.resolve_at_config(&reference, &scope),
        dynamic.resolve(&reference)
    );
    std::env::remove_var(&var);
}

#[test]
fn boot_refuses_a_reference_at_an_undeclared_field() {
    let resolver = SecretResolver::builtins_only();
    let scope = busbar_contract::config_time::ConfigScope::config_time();
    let top = obj(&[("api_base", serde_json::json!({ "env": "GHE_API" }))]);
    let err = resolve_settings(
        &top,
        &declared(&["client_secret"]),
        &[],
        "busbar-auth-github",
        &resolver,
        &scope,
    )
    .unwrap_err();
    assert!(
        err.contains("settings.api_base")
            && err.contains("'busbar-auth-github'")
            && err.contains("did not declare it as a secret")
            && err.contains("write the value itself"),
        "{err}"
    );
    let nested = obj(&[(
        "servers",
        serde_json::json!({ "a": { "headers": { "X": { "file": "/run/k" } } } }),
    )]);
    let err = resolve_settings(
        &nested,
        &declared(&["servers.*.env.*"]),
        &[],
        "p",
        &resolver,
        &scope,
    )
    .unwrap_err();
    assert!(err.contains("settings.servers.a.headers.X"), "{err}");
}

#[test]
fn boot_resolves_references_at_declared_exact_and_wildcard_paths() {
    let var = format!("BUSBAR_DECLARED_FIELD_{}", std::process::id());
    std::env::set_var(&var, "RESOLVED\n");
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[
        ("client_secret", serde_json::json!({ "env": var })),
        (
            "servers",
            serde_json::json!({ "a": { "env": { "API_KEY": { "env": var } }, "command": "run" } }),
        ),
    ]);
    let out = resolve_settings(
        &settings,
        &declared(&["client_secret", "servers.*.env.*"]),
        &[],
        "p",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("declared references resolve");
    assert_eq!(out["client_secret"], serde_json::json!("RESOLVED"));
    assert_eq!(
        out["servers"],
        serde_json::json!({ "a": { "env": { "API_KEY": "RESOLVED" }, "command": "run" } })
    );
    std::env::remove_var(&var);
}

#[test]
fn a_literal_at_a_declared_secret_path_is_refused_without_echo() {
    let resolver = SecretResolver::builtins_only();
    let scope = busbar_contract::config_time::ConfigScope::config_time();
    for (value, shown) in [
        (serde_json::json!("hunter2-bind-pw"), "hunter2-bind-pw"),
        (serde_json::json!(483_920_175_534_u64), "483920175534"),
        (serde_json::json!({ "literal": "wrapped-pw" }), "wrapped-pw"),
    ] {
        let settings = obj(&[
            ("bind_service_password", value),
            ("url", serde_json::json!("ldaps://ldap.example")),
        ]);

        let Err(err) = resolve_settings(
            &settings,
            &declared(&["bind_service_password"]),
            &[],
            "busbar-auth-ldap",
            &resolver,
            &scope,
        ) else {
            panic!("a literal at a declared secret path refuses");
        };
        assert!(
            err.contains("settings.bind_service_password"),
            "names the config position: {err}"
        );
        assert!(
            err.contains(
                "a secret value must be a REFERENCE, never an inline literal (the value is not \
                 echoed)"
            ),
            "the core secret fields' own non-echoing words: {err}"
        );
        assert!(!err.contains(shown), "the value is echoed: {err}");
    }

    let unset = obj(&[("url", serde_json::json!("ldaps://ldap.example"))]);
    resolve_settings(
        &unset,
        &declared(&["bind_service_password"]),
        &[],
        "busbar-auth-ldap",
        &resolver,
        &scope,
    )
    .expect("an unset declared field is not a literal");
}

#[test]
fn a_literal_at_a_wildcard_declared_secret_path_is_refused_without_echo() {
    let resolver = SecretResolver::builtins_only();
    let scope = busbar_contract::config_time::ConfigScope::config_time();
    for (value, shown) in [
        (serde_json::json!("hunter2-wild-pw"), "hunter2-wild-pw"),
        (serde_json::json!(483_920_175_534_u64), "483920175534"),
        (
            serde_json::json!({ "literal": "wrapped-wild-pw" }),
            "wrapped-wild-pw",
        ),
    ] {
        let settings = obj(&[(
            "servers",
            serde_json::json!({ "a": { "env": { "LOG": value }, "command": "run" } }),
        )]);

        let Err(err) = resolve_settings(
            &settings,
            &declared(&["servers.*.env.*"]),
            &[],
            "busbar-plane-x",
            &resolver,
            &scope,
        ) else {
            panic!("a literal at a wildcard declared secret path refuses");
        };
        assert!(
            err.contains("settings.servers.a.env.LOG"),
            "names the config position: {err}"
        );
        assert!(
            err.contains(
                "a secret value must be a REFERENCE, never an inline literal (the value is not \
                 echoed)"
            ),
            "the core secret fields' own non-echoing words: {err}"
        );
        assert!(!err.contains(shown), "the value is echoed: {err}");
    }

    let unset = obj(&[(
        "servers",
        serde_json::json!({ "a": { "env": { "LOG": null }, "command": "run" } }),
    )]);
    resolve_settings(
        &unset,
        &declared(&["servers.*.env.*", "hosts.*.password"]),
        &[],
        "busbar-plane-x",
        &resolver,
        &scope,
    )
    .expect("an unset wildcard match is not a literal");
}

#[test]
fn a_reference_capable_url_resolves_a_reference_and_passes_a_literal() {
    let var = format!("BUSBAR_T_REFCAP_URL_{}", std::process::id());
    std::env::set_var(&var, "postgres://db.internal:5432/busbar\n");
    let resolver = SecretResolver::builtins_only();
    let scope = busbar_contract::config_time::ConfigScope::config_time();
    for plugin in [
        "busbar-store-postgres",
        "busbar-store-valkey",
        "busbar-store-mysql",
        "busbar-hook-webrequest",
    ] {
        let by_ref = obj(&[("url", serde_json::json!({ "env": var }))]);
        let out = resolve_settings(
            &by_ref,
            &declared(&[]),
            &declared(&["url"]),
            plugin,
            &resolver,
            &scope,
        )
        .unwrap_or_else(|e| panic!("{plugin}: a reference-capable url resolves: {e}"));
        assert_eq!(
            out.get("url"),
            Some(&serde_json::json!("postgres://db.internal:5432/busbar")),
            "{plugin}"
        );
        let literal = obj(&[("url", serde_json::json!("redis://cache:6379"))]);
        let out = resolve_settings(
            &literal,
            &declared(&[]),
            &declared(&["url"]),
            plugin,
            &resolver,
            &scope,
        )
        .unwrap_or_else(|e| panic!("{plugin}: a literal url passes: {e}"));
        assert_eq!(
            out.get("url"),
            Some(&serde_json::json!("redis://cache:6379")),
            "{plugin}"
        );
    }
    std::env::remove_var(&var);
}

#[test]
fn a_reference_capable_field_fails_closed_and_leaves_the_secret_rules_whole() {
    let var = format!("BUSBAR_T_REFCAP_UNSET_{}", std::process::id());
    std::env::remove_var(&var);
    let resolver = SecretResolver::builtins_only();
    let scope = busbar_contract::config_time::ConfigScope::config_time();
    let unset = obj(&[("url", serde_json::json!({ "env": var }))]);
    let Err(e) = resolve_settings(
        &unset,
        &declared(&[]),
        &declared(&["url"]),
        "busbar-export-otlp",
        &resolver,
        &scope,
    ) else {
        panic!("an unset variable at a reference-capable field refuses");
    };
    assert!(e.contains("url"), "{e}");

    let secret_literal = obj(&[
        ("url", serde_json::json!("https://siem.example/in")),
        (
            "auth_header",
            serde_json::json!({ "name": "Authorization", "value": "pasted-7a" }),
        ),
    ]);
    let Err(e) = resolve_settings(
        &secret_literal,
        &declared(&["auth_header.value"]),
        &declared(&["url"]),
        "busbar-export-webhook",
        &resolver,
        &scope,
    ) else {
        panic!("a literal at the secret auth_header.value refuses");
    };
    assert!(e.contains("settings.auth_header.value"), "{e}");
    assert!(!e.contains("pasted-7a"), "{e}");

    let Err(e) = resolve_settings(
        &obj(&[("url", serde_json::json!("https://x"))]),
        &declared(&["url"]),
        &declared(&["url"]),
        "acme",
        &resolver,
        &scope,
    ) else {
        panic!("a path in both lists refuses");
    };
    assert!(e.contains("url") && e.contains("'acme'"), "{e}");
}

/// A resolver whose config-time text comes from an allocation it records: where the value it
/// handed out lives.
#[derive(Default)]
struct Recorded(std::sync::Mutex<Vec<usize>>);

impl busbar_contract::secret::SecretResolve for Recorded {
    fn resolve(
        &self,
        _secret: &SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        Err("refused off config time".to_string())
    }

    fn resolve_string(
        &self,
        _secret: &SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        Err("refused off config time".to_string())
    }

    fn resolve_string_at_config(
        &self,
        _secret: &SecretRef,
        _scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        let text = String::from("MOVED-NEVER-COPIED");
        self.0.lock().unwrap().push(text.as_ptr() as usize);
        Ok(busbar_contract::redacted::Secret::new(text))
    }
}

#[test]
fn a_resolved_setting_is_moved_into_the_bag_never_copied() {
    let reference =
        serde_json::json!({ (busbar_contract::secret_ref::SECRET_MODULE_ENV): "UNUSED" });
    let settings = obj(&[("licenseKey", reference.clone()), ("url", reference)]);
    let resolver = Recorded::default();
    let out = resolve_settings(
        &settings,
        &declared(&["licenseKey"]),
        &declared(&["url"]),
        "test-plugin",
        &resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("resolves");
    let handed = resolver.0.lock().unwrap().clone();
    let held: Vec<usize> = ["licenseKey", "url"]
        .iter()
        .map(|k| out[*k].as_str().expect("a string").as_ptr() as usize)
        .collect();
    assert_eq!(held, handed, "each value is the resolver's own allocation");
}

#[test]
fn a_refusal_carries_its_error_kind_through_the_resolver() {
    use busbar_contract::abi::secret::{ERROR_KIND_DENIED, ERROR_KIND_NOT_FOUND};
    use busbar_contract::secret::{SecretRefused, SecretResolve as _};
    let var = format!("BUSBAR_KIND_CARRIED_UNSET_{}", std::process::id());
    std::env::remove_var(&var);
    let unset: SecretRef = serde_json::from_value(
        serde_json::json!({ (busbar_contract::secret_ref::SECRET_MODULE_ENV): var }),
    )
    .expect("a reference");
    let builtins = SecretResolver::builtins_only();
    let refused = builtins
        .resolve_refusing(&unset, None)
        .expect_err("an unset variable does not resolve");
    assert_eq!(refused.error_kind, ERROR_KIND_NOT_FOUND);
    assert_eq!(
        Some(refused.text),
        builtins.resolve(&unset).err(),
        "the text is the resolver's own"
    );

    let plugin = SecretResolver::with_scoped_plugin(Box::new(|_, _, _| {
        Err(SecretRefused {
            error_kind: ERROR_KIND_DENIED,
            text: "not entitled".to_string(),
        })
    }));
    let other: SecretRef =
        serde_json::from_value(serde_json::json!({ "module": "kind-carrier", "settings": {} }))
            .expect("a reference");
    let refused = plugin
        .resolve_refusing(&other, None)
        .expect_err("the plugin refuses");
    assert_eq!(refused.error_kind, ERROR_KIND_DENIED);
    assert!(refused.text.ends_with(": not entitled"), "{}", refused.text);
}
