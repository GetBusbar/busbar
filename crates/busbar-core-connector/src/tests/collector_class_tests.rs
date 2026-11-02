// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OTLP COLLECTOR POLICY AS THE `loopback-allowed` EGRESS CLASS JUDGES IT (ported, not dropped). 1.5.x held the OTLP endpoint to a collector guard (`collector_policy`),

use std::sync::mpsc;
use std::time::Duration;

use super::*;

use busbar_contract::abi::host::conn::connector::{
    EGRESS_DEFAULT, EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_PROVIDER,
};
use busbar_contract::abi::host::service::{DEST_METADATA, DEST_OBFUSCATED};

use crate::guard::Resolved;

/// The collector need's class.
const LA: u32 = EGRESS_LOOPBACK_ALLOWED;

/// The node's own data port, as `own_ports` would read it off `listen`.
const OWN: u16 = 18_080;

/// What the resolver answers, by name (case-blind, as DNS is).
const NAMES: &[(&str, &str)] = &[
    ("localhost", "127.0.0.1"),
    ("api.localhost", "127.0.0.1"),
    ("collector.example.com", "93.184.216.34"),
    ("imds.example.com", "169.254.169.254"),
    ("lo.test", "127.0.0.1"),
    ("lo6.test", "::1"),
    ("ten.test", "10.0.0.1"),
    ("lan.test", "192.168.1.1"),
    ("cgnat.test", "100.64.0.1"),
    ("ula.test", "fd00::1"),
    ("imds.test", "169.254.169.254"),
    ("public.test", "93.184.216.34"),
    ("public6.test", "2606:2800:220:1:248:1893:25c8:1946"),
    ("public.localhost", "93.184.216.34"),
];

/// A resolver answering from [`NAMES`], off the caller's thread.
struct Table;

impl Resolve for Table {
    fn resolve(&self, host: &str, done: Resolved) {
        let answer: Vec<IpAddr> = NAMES
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(host))
            .map(|(_, a)| a.parse().expect("an address"))
            .collect();
        std::thread::spawn(move || {
            done(if answer.is_empty() {
                Err("NXDOMAIN".into())
            } else {
                Ok(answer)
            });
        });
    }
}

/// The deployment's destination judge under the default guard, resolving [`NAMES`].
fn dest_judge() -> GuardJudge {
    GuardJudge::new(Guard::default(), Arc::new(Table))
}

/// The connector's dial judge over [`dest_judge`], the node's own port held off.
fn dial_judge() -> Arc<dyn DialJudge> {
    judge(Arc::new(dest_judge()), &[OWN])
}

/// The connector's dial judge over a guard whose `advanced.allow_destinations` is `allow`

fn allowing(allow: &[&str]) -> Arc<dyn DialJudge> {
    let guard = Guard::from_config(&Destinations {
        block_private_addresses: true,
        allow: allow.iter().map(|a| (*a).to_owned()).collect(),
        ..Destinations::default()
    })
    .expect("a valid allowlist");
    judge(Arc::new(GuardJudge::new(guard, Arc::new(Table))), &[OWN])
}

/// `authority` (`host:port`, as the http framer locates it out of the collector URL), dialled

fn open(
    j: &Arc<dyn DialJudge>,
    authority: &str,
    secure: bool,
    class: u32,
) -> Result<SocketAddr, Verdict> {
    if crate::endpoint::named(authority).is_err() {
        return Err(DEST_NO_HOST);
    }
    if class == EGRESS_OPEN_WEB && !secure {
        return Err(DEST_PLAINTEXT);
    }
    let (tx, rx) = mpsc::channel();
    let judged = j.judge_dial(
        authority,
        class,
        Box::new(move |v| {
            let _ = tx.send(v);
        }),
    );
    let at = judged.unwrap_or_else(|| {
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the judgement answered")
    })?;
    if crate::class_admits(class, secure, &[], authority, at) {
        Ok(at)
    } else {
        Err(DEST_PLAINTEXT)
    }
}

/// RED (ports `test_validate_otlp_endpoint_allows_loopback_collectors`, the external half of

#[test]
fn a_collector_is_reached_in_plaintext_on_loopback_and_over_a_secure_connection_elsewhere() {
    let j = dial_judge();
    for (authority, secure, at) in [
        ("localhost:4318", false, "127.0.0.1:4318"),
        ("LOCALHOST:4318", false, "127.0.0.1:4318"),
        ("localhost:4318", true, "127.0.0.1:4318"),
        ("api.localhost:4318", false, "127.0.0.1:4318"),
        ("127.0.0.1:4318", false, "127.0.0.1:4318"),
        ("127.0.0.1.:4318", false, "127.0.0.1:4318"),
        ("[::1]:4318", false, "[::1]:4318"),
        ("[::ffff:127.0.0.1]:4318", false, "[::ffff:127.0.0.1]:4318"),
        ("[::127.0.0.1]:4318", false, "[::127.0.0.1]:4318"),
        ("collector.example.com:4318", true, "93.184.216.34:4318"),
        ("1.2.3.4:443", true, "1.2.3.4:443"),
        ("1.2.3.4:4318", true, "1.2.3.4:4318"),
    ] {
        assert_eq!(
            open(&j, authority, secure, LA),
            Ok(at.parse().unwrap()),
            "{authority} secure={secure}"
        );
    }
    for authority in ["1.2.3.4:80", "1.2.3.4:4318", "collector.example.com:4318"] {
        assert_eq!(
            open(&j, authority, false, LA),
            Err(DEST_PLAINTEXT),
            "plaintext to a remote collector: {authority}"
        );
    }

    assert_eq!(
        open(&j, "127.0.0.1:4318", false, EGRESS_OPEN_WEB),
        Err(DEST_PLAINTEXT)
    );
    assert_eq!(
        open(&j, "127.0.0.1:4318", true, EGRESS_OPEN_WEB),
        Err(DEST_INTERNAL)
    );
    assert_eq!(
        open(&j, "localhost:4318", true, EGRESS_OPEN_WEB),
        Err(DEST_INTERNAL)
    );
}

/// RED (ports the cloud-metadata rows of

#[test]
fn cloud_metadata_never_reaches_a_collector_in_any_spelling() {
    let j = dial_judge();
    for authority in [
        "169.254.169.254:443",
        "169.254.169.254.:443",
        "metadata.google.internal:443",
        "metadata.google.internal.:443",
        "[::169.254.169.254]:443",
        "[::ffff:169.254.169.254]:443",
        "168.63.129.16:443",
        "192.0.0.192:443",
        "100.100.100.200:443",
        "[fd00:ec2::254]:443",
        "[fe80::1]:443",
        "imds.example.com:443",
    ] {
        for secure in [true, false] {
            assert_eq!(
                open(&j, authority, secure, LA),
                Err(DEST_METADATA),
                "{authority} secure={secure}"
            );
        }
    }
    for url in [
        "HTTPS://169.254.169.254/v1/traces",
        "HTTP://169.254.169.254/v1/traces",
    ] {
        assert!(crate::endpoint::check(url).is_err(), "{url}");
    }
}

/// RED (ports

#[test]
fn an_alternate_ipv4_spelling_of_loopback_reaches_a_collector_as_in_1_5_5() {
    let j = dial_judge();
    for spelling in [
        "127.1",
        "127.0.1",
        "2130706433",
        "0x7f000001",
        "0X7F000001",
        "017700000001",
        "0177.0.0.1",
        "0x7f.0.0.1",
    ] {
        for secure in [false, true] {
            assert_eq!(
                open(&j, &format!("{spelling}:4318"), secure, LA),
                Ok("127.0.0.1:4318".parse().unwrap()),
                "{spelling} secure={secure}"
            );
        }
        for class in [EGRESS_OPEN_WEB, EGRESS_DEFAULT] {
            assert_eq!(
                open(&j, &format!("{spelling}:4318"), true, class),
                Err(DEST_OBFUSCATED),
                "{spelling} class {class}"
            );
        }
    }

    assert_eq!(
        open(&j, &format!("127.1:{OWN}"), false, LA),
        Err(DEST_INTERNAL)
    );

    for authority in ["0xa000001:80", "167772161:80", "0xa000001:443"] {
        for secure in [false, true] {
            assert_eq!(
                open(&j, authority, secure, LA),
                Err(DEST_INTERNAL),
                "{authority} secure={secure}"
            );
        }
    }
    assert_eq!(open(&j, "2852039166:80", false, LA), Err(DEST_METADATA));
    assert!(open(&j, "127.0.0.1:4318", false, LA).is_ok());
}

/// RED (ports the private rows of

#[test]
fn a_private_collector_is_refused_by_default_and_reached_when_allowlisted() {
    let strict = dial_judge();
    for authority in [
        "10.0.0.1:4318",
        "ten.test:4318",
        "192.168.1.1:4318",
        "lan.test:4318",
        "100.64.0.1:4318",
        "cgnat.test:4318",
        "[fd00::1]:4318",
        "ula.test:4318",
    ] {
        assert_eq!(
            open(&strict, authority, true, LA),
            Err(DEST_INTERNAL),
            "{authority}"
        );
    }
    assert!(open(&strict, "93.184.216.34:4318", true, LA).is_ok());
    assert!(open(&strict, "localhost:4318", false, LA).is_ok());
    let allowed = allowing(&["10.0.0.1", "lan.test", "100.64.0.0/10", "fd00::/8"]);
    for (authority, at) in [
        ("10.0.0.1:4318", "10.0.0.1:4318"),
        ("lan.test:4318", "192.168.1.1:4318"),
        ("cgnat.test:4318", "100.64.0.1:4318"),
        ("[fd00::1]:4318", "[fd00::1]:4318"),
    ] {
        assert_eq!(
            open(&allowed, authority, true, LA),
            Ok(at.parse().unwrap()),
            "{authority}"
        );
    }

    assert_eq!(
        open(&allowed, "10.0.0.1:4318", false, LA),
        Err(DEST_PLAINTEXT)
    );

    assert_eq!(
        open(&allowed, "192.168.1.1:4318", true, LA),
        Err(DEST_INTERNAL)
    );
}

/// RED (ports `otlp_resolved_and_literal_verdicts_agree`): one address gets one verdict, written as

#[test]
fn an_address_is_judged_the_same_named_or_written() {
    let j = dial_judge();
    for class in [
        EGRESS_DEFAULT,
        EGRESS_PROVIDER,
        EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_OPEN_WEB,
        LA,
    ] {
        for (name, addr) in NAMES.iter().filter(|(n, _)| n.ends_with(".test")) {
            let ip: IpAddr = addr.parse().unwrap();
            let literal = SocketAddr::new(ip, 443).to_string();
            assert_eq!(
                open(&j, &format!("{name}:443"), true, class),
                open(&j, &literal, true, class),
                "{name} = {addr}, class {class}"
            );
        }
    }
    for (name, admitted) in [
        ("lo.test", true),
        ("lo6.test", true),
        ("public.test", true),
        ("public6.test", true),
        ("ten.test", false),
        ("ula.test", false),
        ("imds.test", false),
    ] {
        assert_eq!(
            open(&j, &format!("{name}:443"), true, LA).is_ok(),
            admitted,
            "{name}"
        );
    }
}

/// RED (ports `test_validate_otlp_endpoint_rejects_bad_scheme`,

#[test]
fn only_an_http_or_https_url_names_a_collector() {
    let j = dest_judge();
    for url in [
        "file:///etc/shadow",
        "ftp://collector.example.com",
        "rpc://collector:4317",
        "HTTPX://collector.example.com",
    ] {
        assert_eq!(j.judge_name(url, LA, false), Err(DEST_SCHEME), "{url}");
    }
    assert_eq!(j.judge_name("", LA, false), Err(DEST_NO_HOST));
    for url in [
        "https://svc:topsecret@10.0.0.1/v1/traces",
        "http://svc:pw0rd@collector.example.com:4318/v1/traces",
        "HTTPS://svc:topsecret@collector.example.com/v1/traces",
    ] {
        assert_eq!(j.judge_name(url, LA, false), Err(DEST_NO_HOST), "{url}");
    }
    for url in [
        "http://localhost:4318/v1/traces",
        "HTTP://localhost:4318/v1/traces",
        "HtTp://127.0.0.1:4318/v1/traces",
        "HTTP://127.1:4318/v1/traces",
        "https://collector.example.com:4318/v1/traces",
        "HTTPS://collector.example.com:4318/v1/traces",
    ] {
        assert_eq!(j.judge_name(url, LA, false), Ok(()), "{url}");
    }

    assert_eq!(
        j.judge_name("HTTP://93.184.216.34:4318/v1/traces", LA, false),
        Err(DEST_PLAINTEXT)
    );
    assert_eq!(
        j.judge_name("HTTPS://169.254.169.254/v1/traces", LA, false),
        Err(DEST_METADATA)
    );

    for class in [
        EGRESS_DEFAULT,
        EGRESS_PROVIDER,
        EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_OPEN_WEB,
        LA,
    ] {
        for (lower, upper) in [
            ("https://93.184.216.34/x", "HTTPS://93.184.216.34/x"),
            ("http://93.184.216.34/x", "Http://93.184.216.34/x"),
        ] {
            assert_eq!(
                j.judge_name(upper, class, false),
                j.judge_name(lower, class, false),
                "{upper}, class {class}"
            );
        }
    }
}

/// RED (ports the plaintext rule of 1.5.5's collector guard,

#[test]
fn plaintext_reaches_a_collector_only_where_its_url_writes_loopback() {
    let j = dial_judge();
    for authority in ["lo.test:4318", "lo6.test:4318", "LO.TEST:4318"] {
        assert_eq!(
            open(&j, authority, false, LA),
            Err(DEST_PLAINTEXT),
            "plaintext to a name answered by loopback: {authority}"
        );
        assert!(
            open(&j, authority, true, LA).is_ok(),
            "the same name over a secure connection: {authority}"
        );
    }
    for (authority, at) in [
        ("public.localhost:4318", "93.184.216.34:4318"),
        ("127.1:4318", "127.0.0.1:4318"),
        ("[::ffff:127.0.0.1]:4318", "[::ffff:127.0.0.1]:4318"),
    ] {
        assert_eq!(
            open(&j, authority, false, LA),
            Ok(at.parse().unwrap()),
            "plaintext to a host written as loopback: {authority}"
        );
    }

    let d = dest_judge();
    let judged = |url: &str| {
        let (tx, rx) = mpsc::channel();
        let now = d.judge(
            url,
            LA,
            false,
            Box::new(move |v| {
                let _ = tx.send(v);
            }),
        );
        now.unwrap_or_else(|| {
            rx.recv_timeout(Duration::from_secs(10))
                .expect("the judgement answered")
        })
        .map(|(at, _)| at)
        .map_err(|r| r.verdict)
    };
    for url in [
        "http://lo.test:4318/v1/traces",
        "HTTP://lo6.test:4318/v1/traces",
    ] {
        assert_eq!(judged(url), Err(DEST_PLAINTEXT), "{url}");
    }
    for (url, at) in [
        ("https://lo.test:4318/v1/traces", "127.0.0.1:4318"),
        (
            "http://public.localhost:4318/v1/traces",
            "93.184.216.34:4318",
        ),
        ("http://localhost:4318/v1/traces", "127.0.0.1:4318"),
        ("http://2130706433:4318/v1/traces", "127.0.0.1:4318"),
    ] {
        assert_eq!(judged(url), Ok(at.parse().unwrap()), "{url}");
    }
}

/// RED (1.5.5's collector guard read an alternate IPv4 spelling as the

#[test]
fn a_spelling_of_a_public_address_is_the_collector_it_spells() {
    let j = dial_judge();
    for spelling in [
        "16909060",
        "0x1020304",
        "0X01020304",
        "1.2.772",
        "0001.0002.0003.0004",
    ] {
        let authority = format!("{spelling}:4318");
        assert_eq!(
            open(&j, &authority, true, LA),
            Ok("1.2.3.4:4318".parse().unwrap()),
            "{spelling}"
        );
        assert_eq!(
            open(&j, &authority, false, LA),
            Err(DEST_PLAINTEXT),
            "{spelling} in plaintext"
        );
        for class in [EGRESS_OPEN_WEB, EGRESS_DEFAULT, EGRESS_PROVIDER] {
            assert_eq!(
                open(&j, &authority, true, class),
                Err(DEST_OBFUSCATED),
                "{spelling} class {class}"
            );
        }
    }
}
