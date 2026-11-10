// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening additions for `busbar_contract::secret_ref` (the former `busbar-secret-ref`

use crate::SecretRef;

/// Source settings may contain credentials even when they look like descriptors.
#[test]
fn secret_ref_settings_retain_authoring_data_without_debug_disclosure() {
    let distinctive_marker = "DISTINCTIVE_OPAQUE_SOURCE_SETTING";
    let reference: SecretRef = serde_json::from_value(serde_json::json!({
        "module":"declared-source", "settings":{"slot":distinctive_marker}
    }))
    .unwrap();
    let debug = format!("{reference:?}");
    assert!(
        !debug.contains(distinctive_marker),
        "opaque source settings leaked: {debug}"
    );
    let wire = serde_json::to_value(reference.writing()).unwrap();
    assert_eq!(wire["settings"]["slot"], distinctive_marker);
    assert_eq!(wire["settings"].as_object().unwrap().len(), 1);
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

/// Generic authoring serialization retains the canonical source document; Debug is redacted.
#[test]
fn secret_ref_serialization_preserves_the_exact_authored_reference() {
    let authored =
        serde_json::json!({"module":"declared-source", "settings":{"slot":"distinctive-marker"}});
    let reference: SecretRef = serde_json::from_value(authored.clone()).unwrap();
    let wire = serde_json::to_value(reference.writing()).unwrap();
    assert_eq!(wire, authored);
    assert_eq!(wire.as_object().unwrap().len(), 2);
    assert!(!format!("{reference:?}").contains("distinctive-marker"));
}
