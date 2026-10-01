// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DESTINATION GUARD: private refused by default, the allowlist admits, metadata stays refused.

use super::*;

use busbar_contract::abi::host::conn::connector::{
    EGRESS_LOOPBACK_ALLOWED, EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_PROVIDER,
};

/// A class whose destinations come from request data: the private refusal holds.
const C: u32 = EGRESS_DEFAULT;

fn guard(block: bool, allow: &[&str]) -> Guard {
    Guard::from_config(&Destinations {
        block_private_addresses: block,
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        ..Destinations::default()
    })
    .expect("a valid allowlist")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn verdict(r: Result<(), Refusal>) -> Option<u64> {
    r.err().map(|r| r.verdict)
}

/// RED: under the default, a name answering a private, loopback, CGNAT or unique-local address is
/// refused as internal; a public answer is admitted.
#[test]
fn a_private_answer_is_refused_by_default() {
    let g = Guard::default();
    for a in [
        "10.0.0.5",
        "127.0.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "fd12::1",
        "::1",
    ] {
        assert_eq!(
            verdict(g.judge_answer("svc.test", &[ip(a)], C)),
            Some(DEST_INTERNAL),
            "{a}"
        );
    }
    assert_eq!(
        g.judge_answer("svc.test", &[ip("93.184.216.34")], C),
        Ok(())
    );
}

/// RED: an allowlist entry admits the private answer it names: a host, a `*.` wildcard, a v4
/// CIDR, a v6 CIDR, and a v4 CIDR over a mapped v6 answer.
#[test]
fn the_allowlist_admits_a_private_answer() {
    let g = guard(
        true,
        &[
            "Ollama.Internal.",
            "*.corp.example",
            "10.0.0.0/8",
            "fd00:1::/32",
        ],
    );
    assert_eq!(
        g.judge_answer("ollama.internal", &[ip("10.9.9.9")], C),
        Ok(())
    );
    assert_eq!(
        g.judge_answer("db.corp.example", &[ip("192.168.1.1")], C),
        Ok(())
    );
    assert_eq!(
        g.judge_answer("a.b.corp.example", &[ip("192.168.1.1")], C),
        Ok(())
    );
    assert_eq!(g.judge_answer("x.test", &[ip("10.1.2.3")], C), Ok(()));
    assert_eq!(
        g.judge_answer("x.test", &[ip("::ffff:10.1.2.3")], C),
        Ok(())
    );
    assert_eq!(g.judge_answer("x.test", &[ip("fd00:1::5")], C), Ok(()));
    // The apex and a suffix without the dot are not under the wildcard.
    for host in ["corp.example", "xcorp.example"] {
        assert_eq!(
            verdict(g.judge_answer(host, &[ip("192.168.1.1")], C)),
            Some(DEST_INTERNAL),
            "{host}"
        );
    }
    assert_eq!(
        verdict(g.judge_answer("x.test", &[ip("fd00:2::5")], C)),
        Some(DEST_INTERNAL)
    );
}

/// RED: a mixed answer is refused whole, never filtered down to its public address.
#[test]
fn a_mixed_answer_is_refused_whole() {
    let g = Guard::default();
    let r = g
        .judge_answer("rebind.test", &[ip("93.184.216.34"), ip("127.0.0.1")], C)
        .unwrap_err();
    assert_eq!((r.verdict, r.addr), (DEST_INTERNAL, Some(ip("127.0.0.1"))));
    assert_eq!(
        r.to_string(),
        "host `rebind.test` resolves to the internal address 127.0.0.1; list it in \
         advanced.allow_destinations to allow it"
    );
    assert_eq!(
        verdict(g.judge_answer("empty.test", &[], C)),
        Some(DEST_NO_ADDRESSES)
    );
}

/// RED (owner Q8): a host entry never admits a metadata answer; an IP or CIDR entry naming the
/// metadata address does.
#[test]
fn a_name_entry_never_admits_a_metadata_answer() {
    let g = guard(true, &["evil.test"]);
    assert_eq!(
        verdict(g.judge_answer("evil.test", &[ip("169.254.169.254")], C)),
        Some(DEST_METADATA)
    );
    let g = guard(true, &["169.254.169.254"]);
    assert_eq!(
        g.judge_answer("evil.test", &[ip("169.254.169.254")], C),
        Ok(())
    );
}

/// RED (owner Q1, Q8): `block_private_addresses: false` admits private answers and names, never
/// cloud metadata.
#[test]
fn block_false_admits_private_but_not_metadata() {
    let g = guard(false, &[]);
    assert_eq!(g.judge_answer("db.test", &[ip("10.0.0.5")], C), Ok(()));
    assert_eq!(g.judge_name("localhost", C), Ok(None));
    assert_eq!(
        verdict(g.judge_answer("x.test", &[ip("169.254.169.254")], C)),
        Some(DEST_METADATA)
    );
    assert_eq!(
        g.judge_name("metadata.google.internal", C)
            .unwrap_err()
            .verdict,
        DEST_METADATA
    );
}

/// The name arm: a literal is judged as its own answer, a `localhost` name and an alternate IPv4
/// spelling are refused before any resolution, a public name passes on to resolution.
#[test]
fn the_name_arm_decides_before_resolution() {
    let g = Guard::default();
    assert_eq!(
        g.judge_name("127.0.0.1", C).unwrap_err().verdict,
        DEST_INTERNAL
    );
    assert_eq!(
        g.judge_name("LOCALHOST.", C).unwrap_err().verdict,
        DEST_INTERNAL
    );
    assert_eq!(
        g.judge_name("0x7f000001", C).unwrap_err().verdict,
        DEST_OBFUSCATED
    );
    assert_eq!(g.judge_name("[::1]", C).unwrap_err().verdict, DEST_INTERNAL);
    assert_eq!(g.judge_name("api.example.com", C), Ok(None));
    assert_eq!(
        g.judge_name("93.184.216.34", C),
        Ok(Some(ip("93.184.216.34")))
    );
    let g = guard(true, &["127.0.0.1", "localhost"]);
    assert_eq!(g.judge_name("127.0.0.1", C), Ok(Some(ip("127.0.0.1"))));
    assert_eq!(g.judge_name("localhost", C), Ok(None));
}

/// The 1.5.5 keys that still load: a carve-out NAME admits its metadata answer (as 1.5.5's did),
/// `allow_all_metadata` admits every metadata name and address, an extra blocked host is refused
/// as metadata unless the allowlist names it.
#[test]
fn the_1_5_5_keys_keep_their_meaning() {
    let legacy = |allow: &[&str], blocked: &[&str], all: bool| {
        Guard::from_config(&Destinations {
            block_private_addresses: true,
            legacy_allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            blocked: blocked.iter().map(|s| (*s).to_owned()).collect(),
            allow_all_metadata: all,
            ..Destinations::default()
        })
        .unwrap()
    };
    let g = legacy(&["imds.corp.example"], &[], false);
    assert_eq!(
        g.judge_answer("imds.corp.example", &[ip("169.254.169.254")], C),
        Ok(())
    );
    let g = legacy(&[], &[], true);
    assert_eq!(g.judge_name("metadata.google.internal", C), Ok(None));
    assert_eq!(
        g.judge_answer("x.test", &[ip("169.254.169.254")], C),
        Ok(())
    );
    let g = legacy(&[], &["imds.corp.example", "203.0.113.9"], false);
    assert_eq!(
        g.judge_name("imds.corp.example", C).unwrap_err().verdict,
        DEST_METADATA
    );
    assert_eq!(
        verdict(g.judge_answer("x.test", &[ip("203.0.113.9")], C)),
        Some(DEST_METADATA)
    );
}

/// A bad allowlist entry refuses the boot, naming the key, its index and the entry (userinfo
/// masked); a CIDR with bits past its prefix is refused too.
#[test]
fn a_bad_entry_is_refused_naming_the_key() {
    let refused = |e: &str| {
        Guard::from_config(&Destinations {
            allow: vec!["ok.test".into(), e.into()],
            ..Destinations::default()
        })
        .unwrap_err()
    };
    assert_eq!(
        refused("http://user:pw@host.test"),
        "advanced.allow_destinations[1]: `<redacted>@host.test` is not a host, a `*.domain` \
         wildcard, an IP or a CIDR"
    );
    for bad in [
        "",
        "host.test:8080",
        "*.",
        "a..b",
        "10.0.0.0/33",
        "*corp.example",
    ] {
        assert!(
            refused(bad).starts_with("advanced.allow_destinations[1]: "),
            "{bad}"
        );
    }
    assert!(refused("10.0.0.1/8").contains("past its prefix length"));
}

/// OWNER Q7 (operator infrastructure EXEMPT) is one table: a destination from request data (the
/// default class, open-web) is refused private; a destination the operator configured (provider,
/// operator infrastructure, loopback-allowed) is trusted, private and loopback included, while
/// cloud metadata, a configured name rebinding to it included, stays refused in every class.
#[test]
fn private_is_refused_for_request_data_and_trusted_for_configured_destinations() {
    let g = Guard::default();
    for class in PRIVATE_REFUSED_IN {
        assert_eq!(
            verdict(g.judge_answer("db.test", &[ip("10.0.0.5")], *class)),
            Some(DEST_INTERNAL)
        );
    }
    for class in [
        EGRESS_PROVIDER,
        EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_LOOPBACK_ALLOWED,
    ] {
        assert_eq!(g.judge_answer("db.test", &[ip("10.0.0.5")], class), Ok(()));
        assert_eq!(g.judge_name("localhost", class), Ok(None));
        assert_eq!(g.judge_name("127.0.0.1", class), Ok(Some(ip("127.0.0.1"))));
        assert_eq!(
            verdict(g.judge_answer("db.test", &[ip("169.254.169.254")], class)),
            Some(DEST_METADATA),
            "a configured name rebinding to metadata, class {class}"
        );
    }
}
