// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`Denylist`] asked of an address: the rule is the one the configuration-time check states,
//! so an address literal gets the same verdict from both.

use crate::trust::net::*;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("an address")
}

fn strings(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

/// ONE RULE: for an address literal, the dial-time verdict and the configuration-time verdict are
/// the same verdict, over the built-in list and over an operator's additions and carve-outs.
#[test]
fn the_dial_verdict_matches_the_configuration_verdict() {
    let blocked = strings(&["10.9.9.9"]);
    let allowed = strings(&["168.63.129.16"]);
    let lists = Denylist::new(&blocked, &allowed, false);
    for literal in [
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "168.63.129.16",
        "192.0.0.192",
        "10.9.9.9",
        "10.9.9.8",
        "127.0.0.1",
        "93.184.216.34",
        "fd00:ec2::254",
        "::ffff:100.100.100.200",
        "::1",
        "fe80::1",
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
