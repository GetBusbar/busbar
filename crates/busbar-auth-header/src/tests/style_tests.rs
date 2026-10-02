// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body: every style binds from its settings, and every refusal is 1.5.5's own
//! words in the `credential:` / `settings:` lines the kernel composes (ARCHITECT ruling Q5); and
//! [`Binding::passthrough`], the caller-credential mode ARCHITECT ruling 2026-09-29 puts on this
//! mechanism's own styles rather than a separate style.

use super::*;

fn open(
    style: &str,
    credential: Option<&str>,
    settings: &str,
) -> (Result<Binding, Vec<Refusal>>, Vec<OpenNote>) {
    let mut notes = Vec::new();
    let r = open_binding(
        style,
        credential.map(str::as_bytes),
        Some(settings.as_bytes()),
        &mut notes,
    );
    (r, notes)
}

fn lines(r: Result<Binding, Vec<Refusal>>) -> Vec<String> {
    r.expect_err("the binding is refused")
        .iter()
        .map(Refusal::line)
        .collect()
}

fn own(r: Result<Binding, Vec<Refusal>>) -> Vec<(String, String)> {
    r.expect("the binding opens").own().to_vec()
}

/// The static styles build their header ONCE, at open, from the default presentation or the
/// dialect's settings.
#[test]
fn the_static_styles_build_their_header_at_open() {
    assert_eq!(
        own(open(BEARER, Some("sk-1"), "{}").0),
        vec![("authorization".to_string(), "Bearer sk-1".to_string())]
    );
    assert_eq!(
        own(open(API_KEY, Some("az-1"), "{}").0),
        vec![("api-key".to_string(), "az-1".to_string())]
    );
    assert_eq!(
        own(open(X_GOOG_API_KEY, Some("g-1"), "").0),
        vec![("x-goog-api-key".to_string(), "g-1".to_string())]
    );
    let table = r#"{"header":"x-api-key","families":[{"prefix":"sk-ant-api","header":"x-api-key","trim_start":true},{"prefix":"sk-ant-oat"}],"passthrough":{}}"#;
    assert_eq!(
        own(open(API_KEY, Some(" sk-ant-api03-k"), table).0),
        vec![("x-api-key".to_string(), "sk-ant-api03-k".to_string())]
    );
    assert_eq!(
        own(open(API_KEY, Some("sk-ant-oat01-k"), table).0),
        vec![(
            "authorization".to_string(),
            "Bearer sk-ant-oat01-k".to_string()
        )]
    );
}

/// No credential (`api_key: none`) presents no header; an un-encodable one presents none and is
/// reported in the line its builder logged.
#[test]
fn a_keyless_or_unencodable_credential_presents_nothing() {
    let (r, notes) = open(BEARER, None, "{}");
    assert!(own(r).is_empty());
    assert!(notes.is_empty(), "keyless is not a fault");
    let (r, notes) = open(BEARER, Some(""), "{}");
    assert!(own(r).is_empty());
    assert!(notes.is_empty());
    let (r, notes) = open(BEARER, Some("sk\r\nx"), "{}");
    assert!(own(r).is_empty());
    assert_eq!(notes, [OpenNote::Bearer]);
    let (r, notes) = open(API_KEY, Some("k\u{0}"), "{}");
    assert!(own(r).is_empty());
    assert_eq!(notes, [OpenNote::Header("api-key".to_string())]);
}

/// A style with no configured credential still presents the CALLER's, in caller mode
/// ([`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]).
#[test]
fn a_style_with_no_own_credential_still_presents_the_callers() {
    let (r, _) = open(X_GOOG_API_KEY, None, "{}");
    let binding = r.expect("the binding opens keyless");
    assert!(binding.own().is_empty(), "no own credential: no own header");
    assert_eq!(
        binding.passthrough("caller-key"),
        vec![("x-goog-api-key".to_string(), "caller-key".to_string())]
    );
    assert!(
        binding.passthrough("").is_empty(),
        "a tokenless caller: no header"
    );
}

/// A family table decides the caller's presentation exactly as it decides the operator's own.
#[test]
fn passthrough_honours_the_family_table_too() {
    let table = r#"{"families":[{"prefix":"sk-ant-oat","header":null}],"own":{"header":"x-api-key"},"passthrough":{"header":"x-api-key"}}"#;
    let (r, _) = open(API_KEY, None, table);
    let binding = r.expect("the binding opens");
    assert_eq!(
        binding.passthrough("sk-ant-oat01-xyz"),
        vec![(
            "authorization".to_string(),
            "Bearer sk-ant-oat01-xyz".to_string()
        )],
        "the family wins over the passthrough default"
    );
    assert_eq!(
        binding.passthrough("other"),
        vec![("x-api-key".to_string(), "other".to_string())]
    );
}

#[test]
fn an_unknown_style_or_malformed_settings_is_refused() {
    assert_eq!(
        lines(open("kerberos", Some("k"), "{}").0),
        ["settings: outbound auth style `kerberos` is not served by this plugin"]
    );
    assert_eq!(
        lines(open(BEARER, Some("k"), "[1]").0),
        ["settings: outbound auth settings must be a JSON object"]
    );
    assert_eq!(
        lines(open("sigv4", Some("k"), "{}").0),
        ["settings: outbound auth style `sigv4` is not served by this plugin"],
        "sigv4 is a different mechanism, busbar-auth-sigv4"
    );
    assert_eq!(
        lines(open("jwt-bearer", Some("k"), "{}").0),
        ["settings: outbound auth style `jwt-bearer` is not served by this plugin"],
        "jwt-bearer is a different mechanism, busbar-auth-oauth"
    );
}

/// THE QUERY STYLE: the credential verbatim under the dialect's parameter (`key` by default), its
/// binding marked as query parameters, never a header; the header styles are not.
#[test]
fn the_query_style_presents_a_query_parameter() {
    let b = open(QUERY_KEY, Some("gem-1"), "{}").0.expect("opens");
    assert!(b.query());
    assert_eq!(b.own(), &[("key".to_string(), "gem-1".to_string())]);
    assert_eq!(
        b.passthrough("caller-1"),
        vec![("key".to_string(), "caller-1".to_string())]
    );
    let named = open(QUERY_KEY, Some("gem-1"), r#"{"param":"api_key"}"#)
        .0
        .expect("opens");
    assert_eq!(named.own(), &[("api_key".to_string(), "gem-1".to_string())]);
    for style in [BEARER, API_KEY, X_GOOG_API_KEY] {
        assert!(
            !open(style, Some("k"), "{}").0.expect("opens").query(),
            "{style}"
        );
    }
    assert!(
        own(open(QUERY_KEY, None, "{}").0).is_empty(),
        "no credential, no parameter"
    );
}
