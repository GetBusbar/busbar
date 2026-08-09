// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dispatch-time SSRF guard: schemes, obfuscated hosts, rebinding, cloud metadata, and
//! redirects. Tool arguments are attacker-controlled, per-request, nested JSON, so this guard is
//! NEW work on the dispatch path rather than a reuse of the startup webhook-URL check — that one
//! validates a single operator-supplied config URL and explicitly disclaims DNS rebinding, which is
//! precisely the threat here.
//!
//! The address checks are driven through [`check_addresses`] with a constructed address list rather
//! than through a resolver, which is the only way to test the case that matters: a resolver
//! answering with one good address and one bad one in a single reply.

use crate::mcp::client::ssrf::{
    check_addresses, precheck, refuse_redirect, resolve_and_pin, SsrfPolicy, SsrfRefusal,
};
use std::net::SocketAddr;

fn public() -> SsrfPolicy {
    SsrfPolicy::default()
}
fn private_ok() -> SsrfPolicy {
    SsrfPolicy {
        allow_private: true,
    }
}

fn sa(s: &str) -> SocketAddr {
    s.parse().expect("test address must parse")
}

#[test]
fn only_http_and_https_are_dispatched_to() {
    let banned = [
        "file:///etc/passwd",
        "gopher://x/",
        "smb://host/share",
        "ftp://host/",
        "data:text/plain,hi",
        "ws://host/",
        "/no-scheme",
        "host.example/mcp",
    ];
    assert_eq!(banned.len(), 8, "the banned-scheme set must not shrink");
    for url in banned {
        assert!(
            matches!(precheck(url, private_ok()), Err(SsrfRefusal::Scheme(_))),
            "`{url}` must be refused on its scheme"
        );
    }
    assert!(precheck("https://ok.example/mcp", public()).is_ok());
}

#[test]
fn plaintext_http_to_a_public_host_is_refused_because_the_credential_rides_the_request() {
    assert!(matches!(
        precheck("http://public.example/mcp", public()),
        Err(SsrfRefusal::PlaintextToPublicHost(_))
    ));
    // ...and is permitted where the operator opted this server into private addressing, which is
    // the real deployment shape for an in-cluster MCP server.
    assert!(precheck("http://mcp.internal:8080/x", private_ok()).is_ok());
}

#[test]
fn userinfo_is_refused_rather_than_stripped() {
    // Two readings of one string: a parser sees `good.example`, a human skimming a diff sees
    // `evil.test`. A value whose readings differ has no place on a dispatch path.
    assert!(matches!(
        precheck("https://evil.test@good.example/mcp", public()),
        Err(SsrfRefusal::NoHost(_))
    ));
}

#[test]
fn alternate_ipv4_encodings_are_refused_before_the_resolver_sees_them() {
    let obfuscated = [
        "https://2130706433/mcp",
        "https://0x7f000001/mcp",
        "https://017700000001/mcp",
        "https://127.1/mcp",
    ];
    assert_eq!(obfuscated.len(), 4);
    for url in obfuscated {
        assert!(
            matches!(precheck(url, public()), Err(SsrfRefusal::ObfuscatedHost(_))),
            "`{url}` must be refused as an obfuscated host"
        );
    }
}

/// THE REBINDING CASE. A resolver answers with a public address AND a loopback address. Checking the
/// first would pass; every address must be checked.
#[test]
fn one_bad_address_among_good_ones_refuses_the_whole_resolution() {
    let addrs = [sa("93.184.216.34:443"), sa("127.0.0.1:443")];
    let err = check_addresses("rebind.example", &addrs, public())
        .expect_err("a loopback address in the answer must refuse the resolution");
    assert_eq!(
        err,
        SsrfRefusal::InternalAddress {
            host: "rebind.example".into(),
            addr: "127.0.0.1".parse().unwrap()
        }
    );
    // Order must not matter: the same answer, reversed, refuses identically.
    let reversed = [sa("127.0.0.1:443"), sa("93.184.216.34:443")];
    assert!(check_addresses("rebind.example", &reversed, public()).is_err());
}

#[test]
fn every_internal_range_is_refused() {
    let internal = [
        "127.0.0.1:443",
        "10.0.0.1:443",
        "172.16.0.1:443",
        "192.168.1.1:443",
        "169.254.1.1:443",
        "100.64.0.1:443",
        "0.0.0.0:443",
        "255.255.255.255:443",
        "224.0.0.1:443",
        "[::1]:443",
        "[fc00::1]:443",
        "[fe80::1]:443",
        "[::]:443",
        // An IPv4-mapped loopback: the v4 ruleset must not be bypassable via a AAAA record.
        "[::ffff:127.0.0.1]:443",
    ];
    assert_eq!(internal.len(), 14, "the internal-range set must not shrink");
    for a in internal {
        assert!(
            check_addresses("h", &[sa(a)], public()).is_err(),
            "{a} must be refused"
        );
    }
    // The CONTROL: a public address is NOT refused, so the loop above is not passing because
    // everything is refused.
    assert!(check_addresses("h", &[sa("93.184.216.34:443")], public()).is_ok());
}

/// CLOUD METADATA IS REFUSED EVEN UNDER `allow_private`. An operator saying "this server is on our
/// internal network" has said nothing about IMDS.
#[test]
fn cloud_metadata_is_refused_unconditionally() {
    let metadata = [
        "169.254.169.254:80",
        "169.254.170.2:80",
        "100.100.100.200:80",
        "[fd00:ec2::254]:80",
    ];
    assert_eq!(metadata.len(), 4);
    for a in metadata {
        for policy in [public(), private_ok()] {
            let err = check_addresses("meta", &[sa(a)], policy)
                .expect_err("{a} must be refused under every policy");
            assert!(
                matches!(err, SsrfRefusal::CloudMetadata { .. }),
                "{a} must be refused AS metadata, got {err:?}"
            );
        }
    }
    // And a private address that is NOT metadata is permitted under `allow_private`, so the
    // unconditional refusal above is specific to metadata rather than to everything.
    assert!(check_addresses("h", &[sa("10.0.0.1:443")], private_ok()).is_ok());
}

#[test]
fn a_redirect_is_refused_and_names_its_target() {
    for status in [301u16, 302, 303, 307, 308] {
        let err = refuse_redirect(status, Some("http://169.254.169.254/latest/meta-data/"))
            .expect_err("a redirect must be refused");
        assert_eq!(
            err,
            SsrfRefusal::Redirect {
                status,
                location: "http://169.254.169.254/latest/meta-data/".into()
            }
        );
    }
    // Non-3xx passes, so the check is about redirects rather than about everything.
    assert!(refuse_redirect(200, None).is_ok());
    assert!(refuse_redirect(404, None).is_ok());
    assert!(refuse_redirect(500, None).is_ok());
}

/// RESOLVE-THEN-PIN end to end against a literal address, so the returned target carries the exact
/// address the check passed and the hostname is preserved for SNI.
#[tokio::test]
async fn a_pinned_target_carries_the_checked_address_and_the_original_host() {
    let t = resolve_and_pin("https://93.184.216.34:8443/mcp", public())
        .await
        .expect("a public literal resolves and pins");
    assert_eq!(t.addr(), sa("93.184.216.34:8443"));
    assert_eq!(t.host(), "93.184.216.34");
    assert_eq!(t.port(), 8443);
    assert!(t.is_https());
}

#[tokio::test]
async fn a_loopback_literal_is_refused_by_default_and_pinned_under_allow_private() {
    assert!(matches!(
        resolve_and_pin("https://127.0.0.1:9000/mcp", public()).await,
        Err(SsrfRefusal::InternalAddress { .. })
    ));
    let t = resolve_and_pin("http://127.0.0.1:9000/mcp", private_ok())
        .await
        .expect("an opted-in private target pins");
    assert_eq!(t.addr(), sa("127.0.0.1:9000"));
    assert!(!t.is_https());
}

#[test]
fn default_ports_are_derived_from_the_scheme() {
    let (https, host, port, path) = precheck("https://a.example/mcp", public()).unwrap();
    assert!(https && host == "a.example" && port == 443 && path == "/mcp");
    let (https, _, port, path) = precheck("http://a.internal", private_ok()).unwrap();
    assert!(!https && port == 80 && path == "/");
}

// ── THE IPv6-EMBEDDED METADATA BYPASS ────────────────────────────────────────────────────────────
//
// `net_guard.rs` documents this exact hazard and names this exact literal, then says why it uses
// `to_ipv4()` and not `to_ipv4_mapped()`: the former is the SUPERSET that also covers the
// IPv4-COMPATIBLE form. This module imported three atoms from `net_guard` and kept its own
// composite, and the composite used the narrower call — so `[::169.254.169.254]` matched no v6
// mask, unwrapped to nothing, and was connected to. Unconditionally: not gated on `allow_private`,
// because the cloud-metadata arm is supposed to refuse before `allow_private` is ever consulted.
//
// These assert the PROPERTY, not the implementation, so they keep biting if the composite ever
// comes back.
#[test]
fn the_ipv4_compatible_form_of_imds_is_refused() {
    let addr: SocketAddr = "[::169.254.169.254]:80".parse().unwrap();
    let err = check_addresses("evil.test", &[addr], SsrfPolicy { allow_private: false })
        .expect_err("[::169.254.169.254] is the AWS IMDS endpoint wearing a v6 costume");
    assert!(
        matches!(err, SsrfRefusal::CloudMetadata { .. }),
        "must be refused AS METADATA, not merely as internal: {err:?}"
    );
}

#[test]
fn the_ipv4_compatible_imds_form_is_refused_even_with_allow_private() {
    let addr: SocketAddr = "[::169.254.169.254]:80".parse().unwrap();
    check_addresses("evil.test", &[addr], SsrfPolicy { allow_private: true })
        .expect_err("cloud metadata is refused unconditionally, `allow_private` or not");
}

#[test]
fn the_ipv4_mapped_form_of_imds_is_refused() {
    let addr: SocketAddr = "[::ffff:169.254.169.254]:80".parse().unwrap();
    check_addresses("evil.test", &[addr], SsrfPolicy { allow_private: true })
        .expect_err("the mapped form is the same endpoint");
}

/// Azure WireServer and OCI IMDS are ORDINARY-LOOKING addresses in no reserved range, so a guard
/// built from range predicates misses them entirely. `net_guard::ipv4_is_internal` names both.
#[test]
fn azure_wireserver_and_oci_imds_are_refused() {
    for lit in ["168.63.129.16:80", "192.0.0.192:80"] {
        let addr: SocketAddr = lit.parse().unwrap();
        check_addresses("evil.test", &[addr], SsrfPolicy { allow_private: false })
            .unwrap_err_or_else_msg(lit);
    }
}

trait UnwrapErrMsg {
    fn unwrap_err_or_else_msg(self, lit: &str);
}
impl UnwrapErrMsg for Result<(), SsrfRefusal> {
    fn unwrap_err_or_else_msg(self, lit: &str) {
        assert!(self.is_err(), "{lit} is a cloud-metadata endpoint and must be refused");
    }
}
