// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening additions for `busbar_contract::secret_ref` (the former `busbar-secret-ref`

use busbar_contract::SecretRef;

/// A `SecretRef` build from a distinctive "looks like a secret" string in its `settings` is

#[test]
fn secret_ref_settings_carry_only_the_reference_never_a_resolved_value() {
    let distinctive_marker = "SUPER_DISTINCTIVE_ENV_VAR_NAME_NOT_A_SECRET_VALUE";
    let r = SecretRef::env(distinctive_marker);
    let debug = format!("{r:?}");

    assert!(
        debug.contains(distinctive_marker),
        "a SecretRef's settings must echo the reference name (env var / file path) in Debug — \
         that name is not secret material: {debug}"
    );

    assert_eq!(r.env_var(), Some(distinctive_marker));
    assert_eq!(
        r.settings.len(),
        1,
        "settings holds only the one reference field"
    );
}

/// `SecretRef` has no `Display` impl at all — grep-proof via a `PartialEq`-shaped compile check is

#[test]
fn secret_ref_debug_output_never_contains_an_inline_literal_a_caller_tried_to_smuggle_in() {
    let distinctive_secret = "sk-DISTINCTIVE-7f3e9c-DO-NOT-ECHO";
    let err = serde_yaml::from_str::<SecretRef>(distinctive_secret)
        .expect_err("a bare scalar is never a secret reference")
        .to_string();
    assert!(
        !err.contains(distinctive_secret),
        "the refusal echoed the literal secret value into the error text: {err}"
    );
    assert!(
        !err.contains("DISTINCTIVE-7f3e9c"),
        "no fragment of the value leaked either: {err}"
    );
}

/// `serde::Serialize` round-trips the same non-secret reference data `Debug` shows — confirming

#[test]
fn secret_ref_serialize_exposes_the_same_reference_data_as_debug_no_more_no_less() {
    let r = SecretRef::file("/run/secrets/distinctive-marker-path");
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["module"], "file");
    assert_eq!(
        json["settings"]["path"],
        "/run/secrets/distinctive-marker-path"
    );

    assert_eq!(json.as_object().unwrap().len(), 2);
}
