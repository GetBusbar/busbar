// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn none_reference_has_no_value_to_resolve() {
    let r = SecretRef::none();
    let resolver = SecretResolver::builtins_only();
    for err in [
        SecretResolver::builtins_only().resolve(&r).unwrap_err(),
        resolver.resolve(&r).unwrap_err(),
        resolver.resolve_string(&r).unwrap_err(),
    ] {
        assert!(
            err.contains("no value to resolve"),
            "`none` never resolves to a value: {err}"
        );
    }
}

#[test]
fn deserialize_accepts_canonical_and_declared_shorthand_rejects_malformed() {
    let r = fixture_authored("{ lookup: MY_VAR }").unwrap();
    assert_eq!(
        r,
        fixture_sources().get("lookup").unwrap().reference("MY_VAR")
    );
    assert_eq!(r.source_module(), Some("first-source"));
    let r = fixture_authored("{ artifact: descriptor }").unwrap();
    assert_eq!(
        r,
        fixture_sources()
            .get("artifact")
            .unwrap()
            .reference("descriptor")
    );
    assert_eq!(r.source_module(), Some("second-source"));
    let r: SecretRef =
        serde_yaml::from_str("{module: independent-source, settings: {slot: opaque}}").unwrap();
    assert_eq!(r.source_module(), Some("independent-source"));
    assert_eq!(
        serde_json::to_value(&r.source().unwrap().settings).unwrap(),
        serde_json::json!({"slot":"opaque"})
    );
    for bad in [
        "{lookup: A, artifact: B}",
        "{module: independent-source, lookup: A}",
        "{lookup: A, settings: {}}",
        "{unknown_key: A}",
        "{}",
        "{lookup: ''}",
        "{module: ''}",
        "plain-string",
    ] {
        assert!(fixture_authored(bad).is_err(), "must reject: {bad}");
    }
}
