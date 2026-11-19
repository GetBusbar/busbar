// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn unknown_source_is_fail_closed_and_names_the_module() {
    let err = SecretResolver::builtins_only()
        .resolve(&fixed_reference("unknown-source"))
        .unwrap_err();
    assert!(err.contains("unknown-source"), "{err}");
    assert!(err.contains("not admitted"), "{err}");
}

#[test]
fn guarded_string_trims_trailing_newlines() {
    let got = fixed_value("text-source", b"top-secret\r\n")
        .resolve_string_at_config(
            &fixed_reference("text-source"),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .unwrap();
    assert_eq!(got.expose(&crate::seal::lend()), "top-secret");
}

#[test]
fn guarded_string_empty_after_trim_is_fail_closed() {
    let err = fixed_value("blank-source", b"\n\r\n")
        .resolve_string_at_config(
            &fixed_reference("blank-source"),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .unwrap_err();
    assert!(
        err.contains("empty") || err.contains("BLANK"),
        "a value with no content must be refused fail-closed: {err}"
    );
    assert!(
        err.contains("blank-source"),
        "the error must name the source: {err}"
    );
}

#[test]
fn guarded_string_non_utf8_is_an_error() {
    let err = fixed_value("binary-source", &[0xff, 0xfe, 0xfd])
        .resolve_string_at_config(
            &fixed_reference("binary-source"),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .unwrap_err();
    assert!(err.contains("non-UTF-8"), "{err}");
}

#[test]
fn guarded_string_propagates_the_underlying_resolve_error() {
    let reference = fixed_reference("refusing-source");
    let resolver = fixed_resolver(vec![(
        reference.clone(),
        Err(SecretRefused {
            error_kind: busbar_contract::secret::codes::ERROR_KIND_NOT_FOUND,
            text: "cannot resolve the requested material".into(),
        }),
    )]);
    let err = resolver
        .resolve_string_at_config(
            &reference,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
}

fn assert_blank_refusal(err: &str) {
    assert!(err.contains("secret module 'blank-source'"), "{err}");
    assert!(err.contains("(BLANK)"), "{err}");
    assert!(err.contains("EMPTY or whitespace-only"), "{err}");
}

#[test]
fn plugin_whitespace_only_bytes_are_refused_on_the_raw_path() {
    let err = fixed_value("blank-source", b" \t\r\n")
        .resolve_at_config(
            &fixed_reference("blank-source"),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .unwrap_err();
    assert_blank_refusal(&err);
}

#[test]
fn plugin_whitespace_only_text_is_refused() {
    let err = fixed_value("blank-source", b"   ")
        .resolve_string_at_config(
            &fixed_reference("blank-source"),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .unwrap_err();
    assert_blank_refusal(&err);
}

#[test]
fn plugin_value_with_content_or_binary_resolves_byte_for_byte() {
    for value in [&b" \tk\r\n "[..], &[0xff, 0x20, 0x0a, 0xfe][..]] {
        let got = fixed_value("binary-source", value)
            .resolve_at_config(
                &fixed_reference("binary-source"),
                &busbar_contract::config_time::ConfigScope::config_time(),
            )
            .unwrap();
        assert_eq!(got, busbar_contract::redacted::Secret::new(value.to_vec()));
    }
}
