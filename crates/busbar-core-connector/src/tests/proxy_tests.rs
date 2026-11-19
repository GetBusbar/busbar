// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ENVIRONMENT, AS THE CONNECTOR HONOURS IT, held to 1.5.5's

use std::ffi::OsString;
use std::sync::Arc;

use super::*;

/// The selected proxy's `host:port` for a target, or `None` for the direct arm.
fn selected(config: &Arc<ProxyChoice>, https: bool, host: &str) -> Option<String> {
    config.select(https, host).map(|p| p.endpoint().to_owned())
}

/// The pure value bag, as the environment would fill it.
fn env(
    https: Option<&str>,
    http: Option<&str>,
    all: Option<&str>,
    no: Option<&str>,
) -> ProxyEnvValues {
    ProxyEnvValues {
        https: https.map(String::from),
        http: http.map(String::from),
        all: all.map(String::from),
        no: no.map(String::from),
    }
}

/// The boot path's ingestion and resolution, with only the OS environment lookup replaced.
fn process_env_config(values: &[(&str, OsString)]) -> Result<Option<Arc<ProxyChoice>>, String> {
    let values = ProxyEnvValues::from_lookup(|key| {
        values
            .iter()
            .find_map(|(name, value)| (*name == key).then(|| value.clone()))
    })?;
    resolve_config(&values)
}

#[test]
fn process_proxy_environment_absence_and_empty_values_allow_direct() {
    assert!(process_env_config(&[]).unwrap().is_none());
    let empty: Vec<_> = [
        HTTPS_PROXY_KEYS,
        HTTP_PROXY_KEYS,
        ALL_PROXY_KEYS,
        NO_PROXY_KEYS,
    ]
    .into_iter()
    .flatten()
    .map(|key| (key, OsString::new()))
    .collect();
    assert!(process_env_config(&empty).unwrap().is_none());
    assert!(
        process_env_config(&[(NO_PROXY_KEYS[0], "internal.corp".into())])
            .unwrap()
            .is_none()
    );
}

#[test]
fn process_proxy_environment_preserves_scheme_and_case_precedence() {
    let config = process_env_config(&[
        (HTTPS_PROXY_KEYS[0], "secure.corp:3128".into()),
        (HTTPS_PROXY_KEYS[1], "http://".into()),
        (HTTP_PROXY_KEYS[0], OsString::new()),
        (HTTP_PROXY_KEYS[1], "plain.corp:8080".into()),
        (ALL_PROXY_KEYS[0], "fallback.corp:8888".into()),
        (ALL_PROXY_KEYS[1], "http://".into()),
        (NO_PROXY_KEYS[0], OsString::new()),
        (NO_PROXY_KEYS[1], "internal.corp".into()),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(
        selected(&config, true, "upstream.test").as_deref(),
        Some("secure.corp:3128")
    );
    assert_eq!(
        selected(&config, false, "upstream.test").as_deref(),
        Some("plain.corp:8080")
    );
    for secured in [true, false] {
        assert!(selected(&config, secured, "db.internal.corp").is_none());
    }

    let fallback = process_env_config(&[
        (HTTPS_PROXY_KEYS[1], "secure.corp:3128".into()),
        (ALL_PROXY_KEYS[0], OsString::new()),
        (ALL_PROXY_KEYS[1], "fallback.corp:8888".into()),
        (NO_PROXY_KEYS[0], "internal.corp".into()),
        (NO_PROXY_KEYS[1], "*".into()),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(
        selected(&fallback, true, "upstream.test").as_deref(),
        Some("secure.corp:3128")
    );
    assert_eq!(
        selected(&fallback, false, "upstream.test").as_deref(),
        Some("fallback.corp:8888")
    );
    assert!(selected(&fallback, false, "internal.corp").is_none());
}

#[test]
fn process_proxy_environment_still_refuses_invalid_urls_without_credentials() {
    const PASSWORD: &str = "env-proxy-password";
    for keys in [HTTPS_PROXY_KEYS, HTTP_PROXY_KEYS, ALL_PROXY_KEYS] {
        let err = process_env_config(&[
            (
                keys[0],
                format!("https://env-user:{PASSWORD}@proxy.corp:3128").into(),
            ),
            (keys[1], "valid.corp:8080".into()),
        ])
        .expect_err("a selected invalid URL must reach the boot refusal");
        assert!(
            !err.contains(PASSWORD) && !err.contains("env-user"),
            "{err}"
        );
        assert!(err.contains("proxy.corp"), "{err}");
    }
}

#[cfg(unix)]
mod non_unicode_environment {
    use std::os::unix::ffi::OsStringExt;

    use super::*;

    fn invalid_value() -> OsString {
        OsString::from_vec(
            b"http://env-user:env-proxy-password\x40private-proxy.corp:\xff".to_vec(),
        )
    }

    fn assert_variable_only_refusal(values: &[(&str, OsString)], key: &str) {
        let err = process_env_config(values)
            .expect_err("selected non-Unicode values must refuse before proxy/direct choice");
        assert_eq!(
            err,
            format!("proxy environment variable {key} is not valid Unicode"),
            "the refusal must contain no value, including credentials or host"
        );
    }

    #[test]
    fn non_unicode_uppercase_refuses_instead_of_using_valid_lowercase() {
        for keys in [
            HTTPS_PROXY_KEYS,
            HTTP_PROXY_KEYS,
            ALL_PROXY_KEYS,
            NO_PROXY_KEYS,
        ] {
            assert_variable_only_refusal(
                &[
                    (keys[0], invalid_value()),
                    (keys[1], "valid.corp:8080".into()),
                ],
                keys[0],
            );
        }
    }

    #[test]
    fn non_unicode_lowercase_refuses_when_uppercase_is_absent_or_empty() {
        for keys in [
            HTTPS_PROXY_KEYS,
            HTTP_PROXY_KEYS,
            ALL_PROXY_KEYS,
            NO_PROXY_KEYS,
        ] {
            assert_variable_only_refusal(&[(keys[1], invalid_value())], keys[1]);
            assert_variable_only_refusal(
                &[(keys[0], OsString::new()), (keys[1], invalid_value())],
                keys[1],
            );
        }
    }

    #[test]
    fn non_unicode_lowercase_is_ignored_after_selected_uppercase() {
        let config = process_env_config(&[
            (HTTPS_PROXY_KEYS[0], "secure.corp:3128".into()),
            (HTTPS_PROXY_KEYS[1], invalid_value()),
            (HTTP_PROXY_KEYS[0], "plain.corp:8080".into()),
            (HTTP_PROXY_KEYS[1], invalid_value()),
            (ALL_PROXY_KEYS[0], "fallback.corp:8888".into()),
            (ALL_PROXY_KEYS[1], invalid_value()),
            (NO_PROXY_KEYS[0], "internal.corp".into()),
            (NO_PROXY_KEYS[1], invalid_value()),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            selected(&config, true, "upstream.test").as_deref(),
            Some("secure.corp:3128")
        );
        assert_eq!(
            selected(&config, false, "upstream.test").as_deref(),
            Some("plain.corp:8080")
        );
        assert!(selected(&config, true, "db.internal.corp").is_none());
    }

    #[test]
    fn non_unicode_all_proxy_and_bypass_list_refuse_even_with_explicit_scheme_slots() {
        for keys in [ALL_PROXY_KEYS, NO_PROXY_KEYS] {
            assert_variable_only_refusal(
                &[
                    (HTTPS_PROXY_KEYS[0], "secure.corp:3128".into()),
                    (HTTP_PROXY_KEYS[0], "plain.corp:8080".into()),
                    (keys[0], invalid_value()),
                ],
                keys[0],
            );
        }
    }
}

#[test]
fn proxy_url_parse_extracts_auth_and_refuses_https_proxies() {
    // A proxy reached over TLS is an operator opt-in, never turned on by a proxy variable's
    // spelling: the environment's `https://` value is refused by name, with or without a port.
    for v in [
        "https://u:p\x40proxy.corp",
        "https://proxy.corp:3128",
        "HTTPS://proxy.corp",
    ] {
        let err = parse_proxy(v).unwrap_err();
        assert!(
            err.contains("https"),
            "an https:// proxy must be refused loudly, naming why: {err}"
        );
    }
    assert!(!parse_proxy("http://proxy.corp:3128").unwrap().secure());
    assert!(!parse_proxy("proxy.corp:3128").unwrap().secure());
    let err = parse_proxy("socks5://proxy.corp:1080").unwrap_err();
    assert!(
        err.contains("socks5"),
        "a proxy scheme that is not spoken is refused by name: {err}"
    );
    assert!(parse_proxy("http://").is_err(), "garbage must not parse");
    assert!(parse_proxy("proxy.corp:3128").is_ok());
    assert!(parse_proxy("http://u:p\x40proxy.corp").is_ok());

    let spec = parse_proxy("http://u:p\x40proxy.corp").unwrap();
    assert_eq!(
        String::from_utf8(connect_request("upstream.test:443", &spec)).unwrap(),
        "CONNECT upstream.test:443 HTTP/1.1\r\nHost: upstream.test:443\r\n\
         Proxy-Authorization: Basic dTpw\r\n\r\n"
    );
    assert_eq!(
        spec.endpoint(),
        "proxy.corp:80",
        "a proxy URL's port defaults to 80"
    );
}

/// (HTTPS_PROXY, HTTP_PROXY, ALL_PROXY) → (https slot, http slot), reqwest's precedence.
#[test]
fn resolve_config_matches_reqwest_precedence() {
    type Row = (
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
    );
    let rows: &[Row] = &[
        (None, None, None, None, None),
        (Some("hs.corp:1"), None, None, Some("hs.corp:1"), None),
        (None, Some("h.corp:2"), None, None, Some("h.corp:2")),
        (
            None,
            None,
            Some("all.corp:3"),
            Some("all.corp:3"),
            Some("all.corp:3"),
        ),
        (
            Some("hs.corp:1"),
            None,
            Some("all.corp:3"),
            Some("hs.corp:1"),
            Some("all.corp:3"),
        ),
        (
            None,
            Some("h.corp:2"),
            Some("all.corp:3"),
            Some("all.corp:3"),
            Some("h.corp:2"),
        ),
        (
            Some("hs.corp:1"),
            Some("h.corp:2"),
            Some("all.corp:3"),
            Some("hs.corp:1"),
            Some("h.corp:2"),
        ),
    ];
    for (https, http, all, want_https, want_http) in rows {
        let config = resolve_config(&env(*https, *http, *all, None)).unwrap();
        match (want_https, want_http) {
            (None, None) => assert!(
                config.is_none(),
                "no proxy vars must resolve to no config: {https:?}/{http:?}/{all:?}"
            ),
            _ => {
                let config = config.expect("some slot is set, a config must exist");
                assert_eq!(
                    selected(&config, true, "api.example.com").as_deref(),
                    *want_https,
                    "https slot for {https:?}/{http:?}/{all:?}"
                );
                assert_eq!(
                    selected(&config, false, "api.example.com").as_deref(),
                    *want_http,
                    "http slot for {https:?}/{http:?}/{all:?}"
                );
            }
        }
    }
}

#[test]
fn resolve_config_fail_louds_on_garbage_in_any_slot() {
    for (https, http, all) in [
        (Some("https://tls-proxy.corp"), None, None),
        (None, Some("http://"), None),
        (None, None, Some("https://tls-proxy.corp")),
    ] {
        assert!(
            resolve_config(&env(https, http, all, None)).is_err(),
            "garbage in {https:?}/{http:?}/{all:?} must refuse to resolve"
        );
    }
}

#[test]
fn bypass_list_suffix_matching_is_conventional() {
    let config = test_config("proxy.corp", 3128, None, "example.com, internal");
    let via = |host: &str| selected(&config, true, host).is_some();
    assert!(!via("example.com"), "exact NO_PROXY entry bypasses");
    assert!(!via("api.example.com"), "domain suffix bypasses");
    assert!(
        via("notexample.com"),
        "a non-boundary suffix must NOT bypass (substring is not a domain match)"
    );
    assert!(!via("INTERNAL"), "matching is case-insensitive");
    assert!(via("api.upstream.test"), "unlisted hosts tunnel");
    let all = test_config("proxy.corp", 3128, None, "*");
    assert!(
        selected(&all, true, "api.upstream.test").is_none(),
        "`*` disables tunneling"
    );
    assert!(no_proxy_matches(".example.com", "example.com"));
    assert!(no_proxy_matches(".example.com", "api.example.com"));
}

#[test]
fn bypass_list_ip_and_cidr_matrix() {
    let m = no_proxy_matches;
    assert!(m("\x310.1.2.3", "\x310.1.2.3"));
    assert!(!m("\x310.1.2.3", "\x310.1.2.30"));
    assert!(!m("\x310.1.2.3", "110.1.2.3"));
    assert!(m("::1", "::1"));
    assert!(m("::1", "[::1]"), "bracketed v6 literal hosts match too");
    assert!(m("\x310.0.0.0/8", "\x310.255.255.255"));
    assert!(m("\x310.0.0.0/8", "\x310.0.0.1"));
    assert!(!m("\x310.0.0.0/8", "11.0.0.0"));
    assert!(!m("\x310.0.0.0/8", "9.255.255.255"));
    assert!(m("0.0.0.0/0", "203.0.113.7"), "/0 matches every v4 address");
    assert!(m("\x3192.168.1.42/32", "\x3192.168.1.42"), "/32 is exact");
    assert!(!m("\x3192.168.1.42/32", "\x3192.168.1.43"));
    assert!(m("\x3192.168.1.0/25", "\x3192.168.1.127"));
    assert!(!m("\x3192.168.1.0/25", "\x3192.168.1.128"));
    assert!(m("fd00::/8", "fd12:3456::1"));
    assert!(!m("fd00::/8", "fe80::1"));
    assert!(m("::/0", "2001:db8::1"), "/0 matches every v6 address");
    assert!(m("2001:db8::1/128", "2001:db8::1"), "/128 is exact");
    assert!(!m("2001:db8::1/128", "2001:db8::2"));
    assert!(!m("\x310.0.0.0/8", "::ffff:\x310.0.0.1"));
    assert!(
        !m("::/0", "\x310.0.0.1"),
        "a v6 catch-all does not catch v4"
    );
    assert!(
        !m("0.0.0.0/0", "2001:db8::1"),
        "a v4 catch-all does not catch v6"
    );
    assert!(!m("0.0.1", "\x310.0.0.1"));
    assert!(!m("\x310.0.0.0/40", "\x310.0.0.1"));
    assert!(m("\x310.0.0.0/40, example.com", "example.com"));
}

#[test]
fn selection_is_scheme_scoped_and_the_bypass_list_excludes_both() {
    let config = resolve_config(&env(
        Some("hs.corp:1"),
        Some("h.corp:2"),
        None,
        Some("internal.corp, \x310.0.0.0/8"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(
        selected(&config, true, "api.upstream.test").as_deref(),
        Some("hs.corp:1")
    );
    assert_eq!(
        selected(&config, false, "api.upstream.test").as_deref(),
        Some("h.corp:2")
    );
    for https in [true, false] {
        assert!(selected(&config, https, "db.internal.corp").is_none());
        assert!(selected(&config, https, "\x310.20.30.40").is_none());
    }
}

#[test]
fn proxy_env_refusals_never_echo_the_proxy_password() {
    const PASSWORD: &str = "hunter2-Pr0xyP@ss";
    let values = [
        "https://svcacct:hunter2-Pr0xyP@ss\x40proxy.corp:3128",
        "http://svcacct:hunter2-Pr0xyP@ss\x40proxy.corp:notaport",
    ];
    for v in values {
        let err = parse_proxy(v).expect_err("both values must be refused");
        assert!(!err.contains(PASSWORD) && !err.contains("hunter2"), "{err}");
        assert!(err.contains("proxy.corp"), "the host survives: {err}");
    }
    for slot in 0..3 {
        let bad = Some(values[0]);
        let err = resolve_config(&env(
            bad.filter(|_| slot == 0),
            bad.filter(|_| slot == 1),
            bad.filter(|_| slot == 2),
            None,
        ))
        .expect_err("a garbage proxy value must refuse to resolve");
        assert!(
            !err.contains(PASSWORD) && !err.contains("hunter2"),
            "slot {slot}: {err}"
        );
    }
}

/// A REFUSAL NAMES THE HOST THE VALUE DIALS, OR NONE. The dialling stack ends a web URL's authority
#[test]
fn a_proxy_refusal_names_no_host_the_value_does_not_dial() {
    for v in [
        "https://proxy.corp\\@victim.example:3128",
        "https://proxy.corp\\u:pw@victim.example",
    ] {
        let err = parse_proxy(v).expect_err("an https:// proxy is refused");
        assert!(!err.contains("victim.example"), "{v}: {err}");
        assert!(!err.contains("pw@"), "{v}: {err}");
    }
}

/// The proxy's answer is read whole before the tunnel is up: an incomplete head waits, a 2xx
#[test]
fn the_proxys_answer_is_judged_on_its_status_line() {
    assert_eq!(connect_answer(b"HTTP/1.1 200 Conn", "t:1"), Ok(None));
    let head = b"HTTP/1.1 200 Connection established\r\n\r\n";
    assert_eq!(connect_answer(head, "t:1"), Ok(Some(head.len())));
    let mut with_target_bytes = head.to_vec();
    with_target_bytes.extend_from_slice(b"\x16\x03");
    assert_eq!(
        connect_answer(&with_target_bytes, "t:1"),
        Ok(Some(head.len()))
    );
    assert_eq!(
        connect_answer(b"HTTP/1.0 204 OK\r\n\r\n", "t:1"),
        Ok(Some(19))
    );
    assert_eq!(
        connect_answer(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "t:1"),
        Err("proxy refused CONNECT t:1: HTTP/1.1 407 Proxy Authentication Required".into())
    );
    assert!(connect_answer(&[b'x'; CONNECT_HEAD_CAP + 1], "t:1").is_err());
    assert_eq!(host_of("upstream.test:8080"), "upstream.test");
    assert_eq!(host_of("[::1]:8080"), "[::1]");
}

/// The proxy credential is percent decoded before it is presented.
#[test]
fn the_proxy_credential_is_percent_decoded_before_it_is_presented() {
    use base64::Engine;
    let spec = parse_proxy("http://svc%40corp:p%40ss%3Aw%25rd\x40proxy.corp:3128").unwrap();
    let expected = format!(
        "Proxy-Authorization: Basic {}\r\n",
        base64::engine::general_purpose::STANDARD.encode("svc@corp:p@ss:w%rd")
    );
    let request = String::from_utf8(connect_request("upstream.test:443", &spec)).unwrap();
    assert!(request.contains(&expected), "{request}");
}

#[test]
fn bypass_list_star_exempts_ip_literals_too() {
    for host in ["\x310.0.0.1", "::1", "[::1]", "api.upstream.test"] {
        assert!(no_proxy_matches("*", host), "`*` exempts {host}");
        assert!(
            no_proxy_matches("example.com, *", host),
            "`*` anywhere in the list exempts {host}"
        );
    }
}

#[test]
fn request_method_env_does_not_disable_proxy() {
    std::env::set_var("REQUEST_METHOD", "GET");
    let config = test_config("proxy.corp", 3128, None, "internal");
    let via = selected(&config, true, "api.upstream.test");
    let exempt = config.exempts("api.upstream.test");
    std::env::remove_var("REQUEST_METHOD");
    assert_eq!(
        via.as_deref(),
        Some("proxy.corp:3128"),
        "the CGI rule never turns a configured proxy off"
    );
    assert!(!exempt, "the CGI rule never widens the exemption list");
}

#[test]
fn bypass_list_unparseable_host_is_not_exempt() {
    for host in [
        "a.com/x",
        "a.com:443",
        "a.com?q",
        "a.com#f",
        "evil.com/a.com",
        "",
    ] {
        assert!(
            !no_proxy_matches("a.com", host),
            "{host:?} must go through the proxy"
        );
    }
}

#[test]
fn bypass_list_userinfo_host_is_not_exempt() {
    assert!(!no_proxy_matches("\x310.0.0.0/8", "x@\x310.0.0.1"));
    assert!(!no_proxy_matches("\x310.0.0.1", "x@\x310.0.0.1"));
    assert!(!no_proxy_matches("a.com", "u\x40a.com"));
    assert!(!no_proxy_matches("a.com", "u:p\x40a.com"));
}
