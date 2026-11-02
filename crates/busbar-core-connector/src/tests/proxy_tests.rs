// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ENVIRONMENT, AS THE CONNECTOR HONOURS IT, held to 1.5.5's

use std::sync::Arc;

use busbar_contract::conn::{ConnError, Conns, NeedId, OpenDesc, Ticket};

use super::*;
use crate::registry::{Entry, Transports};
use crate::support::{worker, TestDoor};
use crate::Connector;

const OWNER: busbar_contract::conn::InstanceId = busbar_contract::conn::InstanceId(1);

/// The selected proxy's `host:port` for a target, or `None` for the direct arm.
fn selected(config: &Arc<ProxyChoice>, https: bool, host: &str) -> Option<String> {
    config.select(https, host).map(|p| p.endpoint())
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
        OsString::from_vec(b"http://env-user:env-proxy-password@private-proxy.corp:\xff".to_vec())
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
    fn non_unicode_all_proxy_and_no_proxy_refuse_even_with_explicit_scheme_slots() {
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
    let err = parse_proxy("https://proxy.corp:3128").unwrap_err();
    assert!(
        err.contains("https"),
        "an https:// proxy must be refused loudly, naming why: {err}"
    );
    assert!(parse_proxy("http://").is_err(), "garbage must not parse");
    assert!(parse_proxy("proxy.corp:3128").is_ok());
    assert!(parse_proxy("http://u:p@proxy.corp").is_ok());

    let spec = parse_proxy("http://u:p@proxy.corp").unwrap();
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
fn no_proxy_suffix_matching_is_conventional() {
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
fn no_proxy_ip_and_cidr_matrix() {
    let m = no_proxy_matches;
    assert!(m("10.1.2.3", "10.1.2.3"));
    assert!(!m("10.1.2.3", "10.1.2.30"));
    assert!(!m("10.1.2.3", "110.1.2.3"));
    assert!(m("::1", "::1"));
    assert!(m("::1", "[::1]"), "bracketed v6 literal hosts match too");
    assert!(m("10.0.0.0/8", "10.255.255.255"));
    assert!(m("10.0.0.0/8", "10.0.0.1"));
    assert!(!m("10.0.0.0/8", "11.0.0.0"));
    assert!(!m("10.0.0.0/8", "9.255.255.255"));
    assert!(m("0.0.0.0/0", "203.0.113.7"), "/0 matches every v4 address");
    assert!(m("192.168.1.42/32", "192.168.1.42"), "/32 is exact");
    assert!(!m("192.168.1.42/32", "192.168.1.43"));
    assert!(m("192.168.1.0/25", "192.168.1.127"));
    assert!(!m("192.168.1.0/25", "192.168.1.128"));
    assert!(m("fd00::/8", "fd12:3456::1"));
    assert!(!m("fd00::/8", "fe80::1"));
    assert!(m("::/0", "2001:db8::1"), "/0 matches every v6 address");
    assert!(m("2001:db8::1/128", "2001:db8::1"), "/128 is exact");
    assert!(!m("2001:db8::1/128", "2001:db8::2"));
    assert!(!m("10.0.0.0/8", "::ffff:10.0.0.1"));
    assert!(!m("::/0", "10.0.0.1"), "a v6 catch-all does not catch v4");
    assert!(
        !m("0.0.0.0/0", "2001:db8::1"),
        "a v4 catch-all does not catch v6"
    );
    assert!(!m("0.0.1", "10.0.0.1"));
    assert!(!m("10.0.0.0/40", "10.0.0.1"));
    assert!(m("10.0.0.0/40, example.com", "example.com"));
}

#[test]
fn selection_is_scheme_scoped_and_no_proxy_excludes_both() {
    let config = resolve_config(&env(
        Some("hs.corp:1"),
        Some("h.corp:2"),
        None,
        Some("internal.corp, 10.0.0.0/8"),
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
        assert!(selected(&config, https, "10.20.30.40").is_none());
    }
}

#[test]
fn proxy_env_refusals_never_echo_the_proxy_password() {
    const PASSWORD: &str = "hunter2-Pr0xyP@ss";
    let values = [
        "https://svcacct:hunter2-Pr0xyP@ss@proxy.corp:3128",
        "http://svcacct:hunter2-Pr0xyP@ss@proxy.corp:notaport",
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

/// A framer over the test carrier, the dial judged by a judge that pins IP literals and finds no

fn proxying(config: Option<Arc<ProxyChoice>>) -> Connector {
    let view = Transports::new(vec![
        Entry {
            door: Arc::new(
                TestDoor::identity("bytes").with_role(busbar_contract::abi::transport::ROLE_FRAMER),
            ),
            alpn: Vec::new(),
        },
        Entry {
            door: Arc::new(TestDoor::identity("carrier")),
            alpn: Vec::new(),
        },
    ])
    .unwrap();
    let judge = |dest: &str, _: u32, _: crate::Judged| {
        Some(
            crate::socket::address_of(dest)
                .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE),
        )
    };
    Connector::serving(view, Arc::new(judge), None, Arc::new(|_, _: Ticket| {})).proxying(config)
}

/// A scripted proxy on loopback: it records the CONNECT head, answers `answer`, and (on a 2xx)

async fn scripted_proxy(answer: &'static [u8]) -> (u16, Arc<std::sync::Mutex<String>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(String::new()));
    let seen2 = Arc::clone(&seen);
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut head = Vec::new();
        let mut buf = [0_u8; 512];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            head.extend_from_slice(&buf[..n]);
        }
        *seen2.lock().unwrap() = String::from_utf8_lossy(&head).into_owned();
        sock.write_all(answer).await.unwrap();
        let mut ping = [0_u8; 4];
        if sock.read_exact(&mut ping).await.is_ok() && &ping == b"ping" {
            let _ = sock.write_all(b"pong").await;
        }
    });
    (port, seen)
}

/// Read until `want` arrived on `id`, or the connection answered an error.
async fn read_until(
    c: &Connector,
    id: busbar_contract::conn::ConnId,
    want: &[u8],
) -> Result<Vec<u8>, ConnError> {
    let mut got = Vec::new();
    let mut buf = [0_u8; 64];
    for _ in 0..5000 {
        match c.read(OWNER, id, 7, &mut buf) {
            Err(ConnError::Pending) => {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await
            }
            Err(e) => return Err(e),
            Ok(p) => {
                got.extend_from_slice(&buf[..p.len]);
                if got.windows(want.len()).any(|w| w == want) {
                    return Ok(got);
                }
            }
        }
    }
    panic!("no answer in five seconds: {got:?}");
}

/// THE PROOF: a framed dial to a name only the proxy resolves goes to the proxy, asks it for the

#[test]
fn a_framed_dial_rides_a_connect_tunnel_through_the_proxy() {
    worker().block_on(async {
        let (port, seen) = scripted_proxy(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
        let c = proxying(Some(test_config(
            "127.0.0.1",
            port,
            Some("Basic dTpw".to_string()),
            "",
        )));
        c.declare_over(OWNER, NeedId(0), "bytes").expect("declares");
        let id = c
            .open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "upstream.test:8080",
                    ..OpenDesc::default()
                },
            )
            .expect("a name the proxy resolves opens");
        assert_eq!(c.write(OWNER, id, b"ping", false, false), Ok(4));
        let got = read_until(&c, id, b"pong")
            .await
            .expect("the target answered");
        assert!(got.ends_with(b"pong"), "{got:?}");
        assert_eq!(
            seen.lock().unwrap().as_str(),
            "CONNECT upstream.test:8080 HTTP/1.1\r\nHost: upstream.test:8080\r\n\
             Proxy-Authorization: Basic dTpw\r\n\r\n",
            "the proxy saw the CONNECT for the real target, and nothing before it"
        );
        c.close(OWNER, id).unwrap();
    });
}

/// RED: a proxy that answers anything but 2xx refuses the exchange; nothing reaches a target.
#[test]
fn a_proxy_refusing_the_tunnel_refuses_the_exchange() {
    worker().block_on(async {
        let (port, seen) =
            scripted_proxy(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        let c = proxying(Some(test_config("127.0.0.1", port, None, "")));
        c.declare_over(OWNER, NeedId(0), "bytes").expect("declares");
        let id = c
            .open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "upstream.test:8080",
                    ..OpenDesc::default()
                },
            )
            .expect("opens");
        assert_eq!(
            read_until(&c, id, b"pong").await,
            Err(ConnError::Refused),
            "the proxy's refusal is the exchange's"
        );
        assert!(seen
            .lock()
            .unwrap()
            .starts_with("CONNECT upstream.test:8080 HTTP/1.1\r\n"));
    });
}

/// THE CLAIM (security.md, "target judged before the proxy is asked"): a target the guard refuses

#[test]
fn a_target_the_guard_refuses_never_reaches_the_proxy() {
    use busbar_contract::abi::host::service::{DEST_INTERNAL, DEST_METADATA};
    worker().block_on(async {
        for (target, verdict) in [
            ("169.254.169.254:80", DEST_METADATA),
            ("10.0.0.5:8080", DEST_INTERNAL),
            ("upstream.test:8080", DEST_INTERNAL),
        ] {
            let (port, seen) = scripted_proxy(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
            let view = Transports::new(vec![
                Entry {
                    door: Arc::new(
                        TestDoor::identity("bytes")
                            .with_role(busbar_contract::abi::transport::ROLE_FRAMER),
                    ),
                    alpn: Vec::new(),
                },
                Entry {
                    door: Arc::new(TestDoor::identity("carrier")),
                    alpn: Vec::new(),
                },
            ])
            .unwrap();
            let refusing = move |_: &str, _: u32, _: crate::Judged| Some(Err(verdict));
            let c = Connector::serving(view, Arc::new(refusing), None, Arc::new(|_, _: Ticket| {}))
                .proxying(Some(test_config("127.0.0.1", port, None, "")));
            c.declare_over(OWNER, NeedId(0), "bytes").expect("declares");
            let opened = c.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target,
                    ..OpenDesc::default()
                },
            );
            let refused = match opened {
                Err(e) => e == ConnError::Refused,
                Ok(id) => read_until(&c, id, b"pong").await == Err(ConnError::Refused),
            };
            assert!(refused, "{target}: a target the guard refuses is refused");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(
                seen.lock().unwrap().is_empty(),
                "{target}: the proxy was asked for a tunnel to a target the guard refused: {:?}",
                seen.lock().unwrap()
            );
        }
    });
}

/// RED: a host `NO_PROXY` names is dialled direct, and a carrier carried as itself (a driver's raw

#[test]
fn no_proxy_and_a_raw_stream_dial_direct() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    worker().block_on(async {
        let (port, seen) = scripted_proxy(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let config = Some(test_config("127.0.0.1", port, None, "127.0.0.1"));
        for (need, scheme) in [(NeedId(0), "bytes"), (NeedId(1), "carrier")] {
            let far = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = far.local_addr().unwrap().to_string();
            tokio::spawn(async move {
                let (mut s, _) = far.accept().await.unwrap();
                let mut ping = [0_u8; 4];
                s.read_exact(&mut ping).await.unwrap();
                s.write_all(b"pong").await.unwrap();
            });

            let c = if scheme == "carrier" {
                proxying(Some(test_config("127.0.0.1", port, None, "")))
            } else {
                proxying(config.clone())
            };
            c.declare_over(OWNER, need, scheme).expect("declares");
            let id = c
                .open(
                    OWNER,
                    need,
                    &OpenDesc {
                        target: &target,
                        ..OpenDesc::default()
                    },
                )
                .expect("opens");
            assert_eq!(c.write(OWNER, id, b"ping", false, false), Ok(4));
            read_until(&c, id, b"pong")
                .await
                .expect("the far end answered direct");
            c.close(OWNER, id).unwrap();
        }
        assert!(seen.lock().unwrap().is_empty(), "the proxy was never asked");
        let direct = proxying(None);
        direct
            .declare_over(OWNER, NeedId(0), "bytes")
            .expect("declares");
        assert_eq!(
            direct.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "upstream.test:8080",
                    ..OpenDesc::default()
                },
            ),
            Err(ConnError::Refused),
            "with no proxy, a name nothing here resolves is refused"
        );
    });
}

/// RED (the proxy environment honoured "exactly as 1.5.5's reqwest clients did"): the proxy URL's

#[test]
fn the_proxy_credential_is_percent_decoded_before_it_is_presented() {
    use base64::Engine;
    let spec = parse_proxy("http://svc%40corp:p%40ss%3Aw%25rd@proxy.corp:3128").unwrap();
    let expected = format!(
        "Proxy-Authorization: Basic {}\r\n",
        base64::engine::general_purpose::STANDARD.encode("svc@corp:p@ss:w%rd")
    );
    let request = String::from_utf8(connect_request("upstream.test:443", &spec)).unwrap();
    assert!(request.contains(&expected), "{request}");
}
