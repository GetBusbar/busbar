// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The route match vocabulary's one spelling of every form: each path form matches what its name
//! says and nothing else, a field name matches in any case while a value prefix matches only in its
//! own case, and a route admits exactly its method set.

use super::*;

#[test]
fn every_method_has_its_own_bit_and_any_holds_them_all() {
    let all = [
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
    ];
    let mut seen = 0;
    for m in all {
        let bit = method_bit(m);
        assert_eq!(bit.count_ones(), 1, "{m}");
        assert_eq!(seen & bit, 0, "{m} shares a bit");
        seen |= bit;
    }
    assert_eq!(seen, METHOD_ANY);
    assert_eq!(method_bit("get"), 0, "a method is its exact spelling");
    assert_eq!(method_bit("BREW"), 0);
}

#[test]
fn each_path_form_matches_what_it_names() {
    assert!(path_matches(PATH_EXACT, "/v1/models", "/v1/models"));
    assert!(!path_matches(PATH_EXACT, "/v1/models", "/v1/models/x"));

    assert!(path_matches(
        PATH_PATTERN,
        "/{name}/v1/messages",
        "/acme/v1/messages"
    ));
    assert!(!path_matches(
        PATH_PATTERN,
        "/{name}/v1/messages",
        "/v1/messages"
    ));
    assert!(path_matches(PATH_PATTERN, "/api/{*rest}", "/api"));
    assert!(path_matches(
        PATH_PATTERN,
        "/api/{*rest}",
        "/api/v1/admin/usage"
    ));
    assert!(!path_matches(PATH_PATTERN, "/api/{*rest}", "/apikeys"));

    assert!(path_matches(PATH_PREFIX, "/a", "/a/b"));
    assert!(!path_matches(PATH_PREFIX, "/a", "/a"));
    assert!(!path_matches(PATH_PREFIX, "/a", "/ab"));
    assert!(!path_matches(PATH_PREFIX, "/a", "/a/b/c"));

    assert!(path_matches(
        PATH_SUFFIX,
        ":generateContent",
        "/v1/models/g:generateContent"
    ));
    assert!(!path_matches(
        PATH_SUFFIX,
        ":generateContent",
        "/v1/models/g:generateContentX"
    ));

    assert!(path_matches(
        PATH_CONTAINS,
        ":stream",
        "/v1/models/g:streamGenerateContent"
    ));
    assert!(!path_matches(PATH_CONTAINS, ":stream", "/v1/models"));

    assert!(
        !path_matches(0, "/", "/"),
        "an unknown form matches nothing"
    );
    assert!(
        !path_matches(PATH_PATTERN, "/{*rest}/x", "/a/x"),
        "a pattern that breaks the syntax matches nothing"
    );
}

#[test]
fn pattern_syntax_is_whole_segments_and_a_last_tail() {
    assert!(pattern_segments("/a/{b}/c").is_some());
    assert!(pattern_segments("/a/{*rest}").is_some());
    assert!(pattern_segments("/a/{*rest}/c").is_none(), "a tail is last");
    assert!(
        pattern_segments("/a/x{b}").is_none(),
        "a variable is a whole segment"
    );
    assert!(pattern_segments("/a/{}").is_none(), "a variable has a name");
    assert!(pattern_segments("/a/{*}").is_none(), "a tail has a name");
}

#[test]
fn a_field_name_matches_in_any_case_and_a_value_prefix_in_its_own() {
    let fields: &[(&str, &[u8])] = &[("Authorization", b"AWS4-HMAC-SHA256 Credential=x")];
    assert!(field_holds(FIELD_PRESENT, "authorization", b"", fields));
    assert!(field_holds(
        FIELD_VALUE_PREFIX,
        "authorization",
        b"AWS4-HMAC-SHA256",
        fields
    ));
    assert!(
        !field_holds(
            FIELD_VALUE_PREFIX,
            "authorization",
            b"aws4-hmac-sha256",
            fields
        ),
        "a value prefix is compared in its own case, as 1.5.5's starts_with was"
    );
    assert!(!field_holds(FIELD_PRESENT, "x-api-key", b"", fields));
}

#[test]
fn a_view_matches_its_path_and_fields_and_admits_only_its_methods() {
    let r = RouteView {
        methods: METHOD_GET | METHOD_POST,
        path_form: PATH_EXACT,
        path: "/v1/messages",
        fields: vec![(FIELD_PRESENT, "anthropic-version", b"".as_slice())],
        rung: 0,
    };
    let with: &[(&str, &[u8])] = &[("Anthropic-Version", b"2023-06-01")];
    assert!(r.path_and_fields_match("/v1/messages", with));
    assert!(
        !r.path_and_fields_match("/v1/messages", &[]),
        "a predicate must hold"
    );
    assert!(r.admits("POST"));
    assert!(
        !r.admits("DELETE"),
        "a path hit on another method is a method miss, not a match"
    );
}

/// RED without the dedup: one string is one copy, and a pattern is parsed once.
#[test]
fn the_interner_returns_one_copy_per_distinct_string() {
    let (a, b) = (intern("/a/literal"), intern("/a/literal"));
    assert!(std::ptr::eq(a, b));
    assert!(!std::ptr::eq(a, intern("/another")));
    let (p, q) = (
        intern_pattern("/m/{x}/{*rest}").unwrap(),
        intern_pattern("/m/{x}/{*rest}").unwrap(),
    );
    assert!(std::ptr::eq(p, q));
    assert!(intern_pattern("/m/{*rest}/x").is_none());
}
