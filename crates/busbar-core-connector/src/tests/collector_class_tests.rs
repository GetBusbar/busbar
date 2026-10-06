// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OTLP COLLECTOR POLICY AS THE `loopback-allowed` EGRESS CLASS JUDGES IT (ARCHITECT rule 15.3:
//! ported, not dropped). 1.5.x held the OTLP endpoint to a collector guard (`collector_policy`),
//! deleted with the cold export lane together with its suite (`crates/busbar/src/root/tests/otlp.rs`)
//! and the root's egress-carrier tests. In 1.6.0 the `busbar-export-otlp` sink declares one outbound
//! need in the `loopback-allowed` class and names the collector itself; the http framer locates the
//! collector URL's authority and whether it is secured, and the connector's open judges that: the
//! endpoint check, the one dial judge ([`judge`] over a [`GuardJudge`], the node's own ports held
//! off), then the class's scheme rule against the pinned address ([`crate::class_admits`]). These
//! tests ask exactly those, in that order, under the production default guard (private addresses
//! blocked, nothing allowlisted).
//!
//! Two of 1.5.x's verdicts are 1.6.0's by ruling and are pinned as 1.6.0 states them, not as 1.5.x
//! did: a private, CGNAT or unique-local collector over a secure connection is admitted in
//! `loopback-allowed` (THE DESIGN §5 egress-class table, owner 2026-09-27; ARCHITECT ruling
//! CRATES-14 scopes the private refusal to the provider and request-data classes), and an alternate
//! IPv4 spelling of loopback is refused like every alternate spelling (the guard judges dotted-quad
//! addresses only).

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
    // One name per address, for the named-or-written comparison.
    ("lo.test", "127.0.0.1"),
    ("lo6.test", "::1"),
    ("ten.test", "10.0.0.1"),
    ("lan.test", "192.168.1.1"),
    ("cgnat.test", "100.64.0.1"),
    ("ula.test", "fd00::1"),
    ("imds.test", "169.254.169.254"),
    ("public.test", "93.184.216.34"),
    ("public6.test", "2606:2800:220:1:248:1893:25c8:1946"),
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

/// `authority` (`host:port`, as the http framer locates it out of the collector URL), dialled
/// `secure` or in plaintext by a plugin-named need in `class`, judged as the connector's open judges
/// it: the endpoint check, open-web's plaintext refusal, the dial judgement (waiting out a
/// resolution), the class's scheme rule on the pinned address. The endpoint check's refusal reads as
/// [`DEST_METADATA`], the scheme rule's as [`DEST_PLAINTEXT`].
fn open(
    j: &Arc<dyn DialJudge>,
    authority: &str,
    secure: bool,
    class: u32,
) -> Result<SocketAddr, Verdict> {
    if crate::endpoint::check(authority).is_err() {
        return Err(DEST_METADATA);
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
    if crate::class_admits(class, secure, &[], at) {
        Ok(at)
    } else {
        Err(DEST_PLAINTEXT)
    }
}

/// RED (ports `test_validate_otlp_endpoint_allows_loopback_collectors`, the external half of
/// `test_validate_otlp_endpoint_accepts_none_and_external`,
/// `test_validate_otlp_endpoint_requires_https_for_remote_collector`,
/// `otlp_resolve_check_allows_a_name_resolving_to_loopback` and the loopback arm of
/// `test_validate_otlp_endpoint_rejects_trailing_dot_internal_hosts`; the RED arm ports the open-web
/// arm of `the_collector_policy_carries_octets_to_a_loopback_collector_and_nothing_else`): a
/// collector need reaches a loopback collector in plaintext, by literal (a trailing root dot
/// included) or by a name resolving to loopback (`localhost`, `*.localhost`, any case), and a
/// remote collector over a secure connection only; a plaintext remote collector is refused. RED
/// ARM: the same loopback collector under open-web (the class an undeclared sink's webhook gets) is
/// refused, plaintext or not.
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
    // RED ARM: open-web refuses the loopback collector, whatever its scheme.
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

/// RED (ports the cloud-metadata rows of `test_validate_otlp_endpoint_rejects_cloud_metadata_and_internal`,
/// `test_validate_otlp_endpoint_rejects_trailing_dot_internal_hosts`, the guard half of
/// `test_validate_otlp_endpoint_accepts_uppercase_scheme`, and the metadata rows of
/// `the_collector_policy_carries_octets_to_a_loopback_collector_and_nothing_else`): a collector need
/// never reaches cloud metadata — the link-local IMDS, the metadata names, a trailing root dot, the
/// IPv4-compatible and -mapped spellings, Azure's WireServer, OCI's and Alibaba's endpoints, EC2's
/// IPv6 IMDS, IPv6 link-local, and a name resolving to IMDS — over a secure connection or not; and
/// a URL's scheme spelling decides nothing about the host it names.
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

/// RED (ports `test_validate_otlp_endpoint_rejects_alternate_encoded_internal`): an alternate IPv4
/// spelling never reaches a collector — an internal one is refused as the spelling it is, and
/// IMDS's decimal spelling as metadata. 1.6.0 refuses the alternate spellings of loopback too (the
/// guard judges dotted-quad addresses only; 1.5.x's collector carve-out admitted them): the dotted
/// form is the one a collector is reached at.
#[test]
fn an_alternate_ipv4_spelling_never_reaches_a_collector() {
    let j = dial_judge();
    for authority in [
        "0xa000001:80",
        "167772161:80",
        "2130706433:4318",
        "0x7f000001:4318",
        "127.1:4318",
    ] {
        assert_eq!(
            open(&j, authority, false, LA),
            Err(DEST_OBFUSCATED),
            "{authority}"
        );
    }
    assert_eq!(open(&j, "2852039166:80", false, LA), Err(DEST_METADATA));
    assert!(open(&j, "127.0.0.1:4318", false, LA).is_ok());
}

/// RED (ports `otlp_resolved_and_literal_verdicts_agree`): one address gets one verdict, written as
/// a literal or reached through a name that resolves to it, in every egress class — a name and a
/// literal spelling of one address that disagree are what make a guard bypassable. Under the
/// collector's class, loopback and public addresses are admitted and metadata refused either way.
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
        ("imds.test", false),
    ] {
        assert_eq!(
            open(&j, &format!("{name}:443"), true, LA).is_ok(),
            admitted,
            "{name}"
        );
    }
}

/// RED (ports `test_validate_otlp_endpoint_rejects_bad_scheme` and the userinfo arm of
/// `test_validate_otlp_endpoint_error_masks_userinfo`, on the destination judge's URL arm, the one
/// the host's `dest.judge` and the kernel's own clients ask): only an `http` or `https` URL names a
/// destination; an empty one names none; a URL carrying userinfo is refused as naming no host, a
/// verdict code that carries none of it.
#[test]
fn only_an_http_or_https_url_names_a_collector() {
    let j = dest_judge();
    for url in [
        "file:///etc/shadow",
        "ftp://collector.example.com",
        "grpc://collector:4317",
    ] {
        assert_eq!(j.judge_name(url, LA), Err(DEST_SCHEME), "{url}");
    }
    assert_eq!(j.judge_name("", LA), Err(DEST_NO_HOST));
    for url in [
        "https://svc:topsecret@10.0.0.1/v1/traces",
        "http://svc:pw0rd@collector.example.com:4318/v1/traces",
    ] {
        assert_eq!(j.judge_name(url, LA), Err(DEST_NO_HOST), "{url}");
    }
    assert_eq!(j.judge_name("http://localhost:4318/v1/traces", LA), Ok(()));
    assert_eq!(
        j.judge_name("https://collector.example.com:4318/v1/traces", LA),
        Ok(())
    );
}
