// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dial table: the configuration-time metadata denylist, asked of the addresses a name resolves
//! to when it is dialled. Metadata and operator-blocked addresses are refused; private and loopback
//! addresses pass as they pass at configuration time; a provider's own carve-out admits its host
//! only; `allow_all` admits everything; and the rule is the one the configuration-time check states,
//! so an address literal gets the same verdict from both.

use crate::trust::net::*;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("an address")
}

fn strings(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

#[test]
fn metadata_answers_are_refused_and_private_answers_pass() {
    let table = DialDenylist::default();
    for bad in ["169.254.169.254", "100.100.100.200", "168.63.129.16", "192.0.0.192", "fd00:ec2::254", "::ffff:169.254.169.254"] {
        assert_eq!(
            table.judge("api.example.com", &[ip(bad)]),
            Err(AddressRefusal::CloudMetadataAddress {
                host: "api.example.com".to_string(),
                addr: ip(bad),
            }),
            "{bad}"
        );
    }
    for good in ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.9", "100.64.0.1", "93.184.216.34"] {
        assert_eq!(table.judge("api.example.com", &[ip(good)]), Ok(()), "{good}");
    }
}

#[test]
fn a_mixed_answer_is_refused_whole() {
    let table = DialDenylist::default();
    assert!(table
        .judge("api.example.com", &[ip("93.184.216.34"), ip("169.254.169.254")])
        .is_err());
}

#[test]
fn an_operator_blocked_address_is_refused() {
    let table = DialDenylist::new(&strings(&["10.9.9.9"]), &[], false, std::iter::empty());
    assert!(table.judge("internal.example", &[ip("10.9.9.9")]).is_err());
    assert!(table.judge("internal.example", &[ip("10.9.9.8")]).is_ok());
}

#[test]
fn a_provider_carve_out_admits_its_own_host_only() {
    let own = strings(&["169.254.169.254"]);
    let table = DialDenylist::new(
        &[],
        &[],
        false,
        [("IMDS.example.".to_string(), own.as_slice())],
    );
    assert!(table.judge("imds.example", &[ip("169.254.169.254")]).is_ok());
    assert!(table.judge("other.example", &[ip("169.254.169.254")]).is_err());

    // A carve-out may name the host instead of the address.
    let by_name = strings(&["named.example"]);
    let table = DialDenylist::new(
        &[],
        &[],
        false,
        [("named.example".to_string(), by_name.as_slice())],
    );
    assert!(table.judge("named.example", &[ip("169.254.169.254")]).is_ok());
}

#[test]
fn the_global_carve_out_and_allow_all_reach_every_host() {
    let table = DialDenylist::new(&[], &strings(&["169.254.169.254"]), false, std::iter::empty());
    assert!(table.judge("any.example", &[ip("169.254.169.254")]).is_ok());
    let table = DialDenylist::new(&strings(&["10.9.9.9"]), &[], true, std::iter::empty());
    assert!(table.judge("any.example", &[ip("169.254.169.254"), ip("10.9.9.9")]).is_ok());
}

/// ONE RULE: for an address literal, the dial-time verdict and the configuration-time verdict are
/// the same verdict, over the built-in list and over an operator's additions and carve-outs.
#[test]
fn the_dial_verdict_matches_the_configuration_verdict() {
    let blocked = strings(&["10.9.9.9"]);
    let allowed = strings(&["168.63.129.16"]);
    let lists = Denylist::new(&blocked, &allowed, false);
    for literal in [
        "169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16", "192.0.0.192",
        "10.9.9.9", "10.9.9.8", "127.0.0.1", "93.184.216.34", "fd00:ec2::254",
        "::ffff:100.100.100.200", "::1",
    ] {
        let addr = ip(literal);
        let url = match addr {
            IpAddr::V4(_) => format!("https://{literal}/v1"),
            IpAddr::V6(_) => format!("https://[{literal}]/v1"),
        };
        assert_eq!(
            lists.refuses_address(literal, addr),
            ssrf_blocked_host(&url, &allowed, false, &blocked).is_some(),
            "{literal}"
        );
    }
}
