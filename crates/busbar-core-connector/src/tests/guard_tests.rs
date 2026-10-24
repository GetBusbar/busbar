// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DESTINATION GUARD: private refused by default, the allowlist admits, metadata stays refused.

use super::*;

use busbar_contract::abi::host::conn::connector::{
    EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    EGRESS_PROVIDER,
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

/// The 1.5.5 keys that still load: for a provider dial, a carve-out NAME admits its metadata
/// answer (as 1.5.5's did) and `allow_all_metadata` admits every metadata name and address; in any
/// other class neither admits anything. An extra blocked host is refused as metadata unless the
/// allowlist names it.
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
        g.judge_answer(
            "imds.corp.example",
            &[ip("169.254.169.254")],
            EGRESS_PROVIDER
        ),
        Ok(())
    );
    let g = legacy(&[], &[], true);
    assert_eq!(
        g.judge_name("metadata.google.internal", EGRESS_PROVIDER),
        Ok(None)
    );
    assert_eq!(
        g.judge_answer("x.test", &[ip("169.254.169.254")], EGRESS_PROVIDER),
        Ok(())
    );
    let carved = legacy(&["imds.corp.example", "169.254.169.254"], &[], true);
    for class in [
        C,
        EGRESS_OPEN_WEB,
        EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_LOOPBACK_ALLOWED,
    ] {
        assert_eq!(
            verdict(carved.judge_answer("imds.corp.example", &[ip("169.254.169.254")], class)),
            Some(DEST_METADATA),
            "class {class}"
        );
        assert_eq!(
            carved
                .judge_name("metadata.google.internal", class)
                .unwrap_err()
                .verdict,
            DEST_METADATA,
            "class {class}"
        );
    }
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

/// A provider's own carve-out (`providers.<p>.allow_metadata_hosts`) admits for a provider dial of
/// a host that provider's URLs name, and for no other host: another provider's, or one no
/// provider names.
#[test]
fn a_provider_carve_out_admits_only_for_its_own_url_host() {
    let g = Guard::from_config(&Destinations {
        block_private_addresses: true,
        url_allow: vec![
            (
                "https://IMDS-Proxy.test./v1".into(),
                vec!["169.254.169.254".into()],
            ),
            (
                "https://token.test/oauth".into(),
                vec!["169.254.169.254".into()],
            ),
            ("https://other.test".into(), Vec::new()),
        ],
        ..Destinations::default()
    })
    .unwrap();
    let imds = [ip("169.254.169.254")];
    for host in ["imds-proxy.test", "token.test"] {
        assert_eq!(
            g.judge_answer(host, &imds, EGRESS_PROVIDER),
            Ok(()),
            "{host}"
        );
    }
    for host in ["other.test", "unnamed.test"] {
        assert_eq!(
            verdict(g.judge_answer(host, &imds, EGRESS_PROVIDER)),
            Some(DEST_METADATA),
            "{host}"
        );
    }
    assert_eq!(
        verdict(g.judge_answer("imds-proxy.test", &imds, C)),
        Some(DEST_METADATA)
    );
}

/// A config commit re-publishes the metadata lists to every clone of the guard: a carve-out the
/// commit removes is refused at the next judgement, and one it adds is admitted.
#[test]
fn a_commit_republishes_the_metadata_lists() {
    let carved = Destinations {
        block_private_addresses: true,
        url_allow: vec![(
            "https://imds-proxy.test".into(),
            vec!["169.254.169.254".into()],
        )],
        ..Destinations::default()
    };
    let g = Guard::from_config(&carved).unwrap();
    let held = g.clone();
    let imds = [ip("169.254.169.254")];
    assert_eq!(
        held.judge_answer("imds-proxy.test", &imds, EGRESS_PROVIDER),
        Ok(())
    );
    g.publish(&Destinations {
        block_private_addresses: true,
        ..Destinations::default()
    });
    assert_eq!(
        verdict(held.judge_answer("imds-proxy.test", &imds, EGRESS_PROVIDER)),
        Some(DEST_METADATA)
    );
    g.publish(&carved);
    assert_eq!(
        held.judge_answer("imds-proxy.test", &imds, EGRESS_PROVIDER),
        Ok(())
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

/// THE DEFAULT POLICY is one table: the provider class and a destination from request data (the
/// default class, open-web) are refused private (THE DESIGN §5 destination guard, ARCHITECT ruling
/// CRATES-14); operator infrastructure is allowed private and loopback (§5 egress-class table,
/// owner 2026-09-27); loopback-allowed is allowed loopback and refused every other private address
/// (ARCHITECT parity ruling A2: the destination guard still applying, as 1.5.5's collector guard
/// refused them); while cloud metadata, a configured name rebinding to it included, stays refused
/// in every class.
#[test]
fn private_is_refused_for_providers_and_request_data_and_allowed_for_operator_infrastructure() {
    let g = Guard::default();
    for class in PRIVATE_REFUSED_IN {
        assert_eq!(
            verdict(g.judge_answer("db.test", &[ip("10.0.0.5")], *class)),
            Some(DEST_INTERNAL)
        );
    }
    assert!(PRIVATE_REFUSED_IN.contains(&EGRESS_PROVIDER));
    assert_eq!(
        g.judge_answer("db.test", &[ip("10.0.0.5")], EGRESS_OPERATOR_INFRASTRUCTURE),
        Ok(())
    );
    assert_eq!(
        verdict(g.judge_answer("db.test", &[ip("10.0.0.5")], EGRESS_LOOPBACK_ALLOWED)),
        Some(DEST_INTERNAL)
    );
    for class in [EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_LOOPBACK_ALLOWED] {
        assert_eq!(g.judge_name("localhost", class), Ok(None));
        assert_eq!(g.judge_name("127.0.0.1", class), Ok(Some(ip("127.0.0.1"))));
        assert_eq!(
            verdict(g.judge_answer("db.test", &[ip("169.254.169.254")], class)),
            Some(DEST_METADATA),
            "a configured name rebinding to metadata, class {class}"
        );
    }
}

/// RED (THE DESIGN §5 destination guard, ARCHITECT ruling CRATES-14 on Q130/Q131: "the 'refused
/// unless allowlisted' default applies to the provider and IdP egress classes only"): a provider
/// dial with no allowlist entry for it is refused a private or loopback address, by name, by
/// literal and by answer; the allowlist admits it; a HOST allowlist entry still never admits a
/// metadata answer, and no 1.5.5 carve-out admits metadata for a host the provider does not name.
#[test]
fn a_provider_dial_is_refused_a_private_address_unless_allowlisted() {
    let strict = Guard::default();
    let p = EGRESS_PROVIDER;
    assert_eq!(
        verdict(strict.judge_answer("model.internal", &[ip("10.0.0.5")], p)),
        Some(DEST_INTERNAL)
    );
    assert_eq!(
        strict.judge_name("127.0.0.1", p).unwrap_err().verdict,
        DEST_INTERNAL
    );
    assert_eq!(
        strict.judge_name("localhost", p).unwrap_err().verdict,
        DEST_INTERNAL
    );
    let allowed = guard(true, &["model.internal", "127.0.0.1", "localhost"]);
    assert_eq!(
        allowed.judge_answer("model.internal", &[ip("10.0.0.5")], p),
        Ok(())
    );
    assert_eq!(
        allowed.judge_name("127.0.0.1", p),
        Ok(Some(ip("127.0.0.1")))
    );
    assert_eq!(allowed.judge_name("localhost", p), Ok(None));
    assert_eq!(
        verdict(allowed.judge_answer("model.internal", &[ip("169.254.169.254")], p)),
        Some(DEST_METADATA),
        "a host entry never admits a metadata answer"
    );
    let carved = Guard::from_config(&Destinations {
        block_private_addresses: true,
        url_allow: vec![(
            "https://imds-proxy.test".into(),
            vec!["169.254.169.254".into()],
        )],
        ..Destinations::default()
    })
    .unwrap();
    assert_eq!(
        verdict(carved.judge_answer("model.internal", &[ip("169.254.169.254")], p)),
        Some(DEST_METADATA),
        "another provider's carve-out admits nothing here"
    );
    assert_eq!(
        verdict(carved.judge_answer("model.internal", &[ip("10.0.0.5")], p)),
        Some(DEST_INTERNAL),
        "a metadata carve-out is no private allowance"
    );
}

/// THE DESIGN §5 egress-class table (owner-signed 2026-09-27), held beside the provider fix above:
/// operator infrastructure is allowed private and loopback with no allowlist entry, and refuses cloud metadata even when the
/// allowlist names the host and every 1.5.5 carve-out names the address.
#[test]
fn operator_infrastructure_is_allowed_private_and_refused_metadata_whatever_is_carved() {
    let oi = EGRESS_OPERATOR_INFRASTRUCTURE;
    let strict = Guard::default();
    assert_eq!(
        strict.judge_answer("db.test", &[ip("10.0.0.5")], oi),
        Ok(())
    );
    assert_eq!(
        strict.judge_name("127.0.0.1", oi),
        Ok(Some(ip("127.0.0.1")))
    );
    let carved = Guard::from_config(&Destinations {
        block_private_addresses: true,
        allow: vec!["db.test".into()],
        legacy_allow: vec!["169.254.169.254".into(), "db.test".into()],
        url_allow: vec![(
            "https://db.test".into(),
            vec!["169.254.169.254".into(), "db.test".into()],
        )],
        allow_all_metadata: true,
        ..Destinations::default()
    })
    .unwrap();
    assert_eq!(
        verdict(carved.judge_answer("db.test", &[ip("169.254.169.254")], oi)),
        Some(DEST_METADATA)
    );
    assert_eq!(
        carved
            .judge_name("metadata.google.internal", oi)
            .unwrap_err()
            .verdict,
        DEST_METADATA
    );
}

/// RED (THE DESIGN §5 "no blocking thread exists"; resource bounds): the dial guard's name
/// lookups are CAPPED (`MAX_PENDING_LOOKUPS`): with the cap's lookups in flight one more is
/// answered at once as a resolution failure and starts no thread. Uncapped, one thread was started per lookup, so a burst of dials while names were slow
/// grew threads without limit.
#[test]
fn a_lookup_past_the_cap_is_refused_at_once_and_starts_no_thread() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::{mpsc, Condvar, Mutex};
    use std::time::Duration;

    static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (answer, answered) = mpsc::channel();
    for i in 0..3_u32 {
        let (gate, answer) = (Arc::clone(&gate), answer.clone());
        super::resolve_capped(
            "slow.example",
            Box::new(move |r| {
                let _ = answer.send((i, r.is_ok()));
            }),
            2,
            &IN_FLIGHT,
            move |_| {
                let (open, opened) = &*gate;
                let mut is_open = open.lock().unwrap();
                while !*is_open {
                    is_open = opened.wait(is_open).unwrap();
                }
                Ok(Vec::new())
            },
        );
    }
    let first = answered.recv_timeout(Duration::from_secs(2));
    {
        let (open, opened) = &*gate;
        *open.lock().unwrap() = true;
        opened.notify_all();
    }
    assert_eq!(
        first,
        Ok((2, false)),
        "the lookup past the cap is refused at once"
    );
    let mut rest: Vec<(u32, bool)> = (0..2)
        .map(|_| answered.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect();
    rest.sort_unstable();
    assert_eq!(rest, [(0, true), (1, true)], "the two in flight answer");
}

/// A CONFIGURED OPEN-WEB TARGET KEEPS THE OPEN-WEB CLASS (Q128 arch u22/u23 BLOCK; ruling 14: "a
/// configured open-web target keeps the open-web class (public https only); only the egress
/// default class is lifted when configured"; 1.5.5's webhook export refused a private or loopback
/// URL). A webhook URL taken from settings is judged open-web, so `https://127.0.0.1` and a
/// `10.x` address are refused; only the egress default is lifted to operator infrastructure.
/// RED before the fix: the configured open-web need was lifted, and both were admitted.
#[test]
fn a_configured_open_web_target_keeps_its_class_and_is_refused_a_private_address() {
    assert_eq!(judged_class(EGRESS_OPEN_WEB, true), EGRESS_OPEN_WEB);
    assert_eq!(
        judged_class(EGRESS_DEFAULT, true),
        EGRESS_OPERATOR_INFRASTRUCTURE
    );
    let g = Guard::default();
    for a in ["127.0.0.1", "10.0.0.7"] {
        assert_eq!(
            verdict(g.judge_answer(a, &[ip(a)], judged_class(EGRESS_OPEN_WEB, true))),
            Some(DEST_INTERNAL),
            "a configured webhook to {a}"
        );
    }
}

/// RED (Q128 arch u22 HIGH 2; ARCHITECT PB-100: metadata and link-local are refused on every need,
/// whatever its egress class): the guard, the one metadata and link-local refusal a judged dial
/// meets, refuses an IPv6 link-local answer in every class, operator infrastructure included, with
/// the endpoint check's verdict; only an IP or CIDR entry naming the address admits it (the
/// allowlist's in any class, a provider carve-out's for a provider dial). A host entry, a private
/// reach, `allow_all_metadata` and `block_private_addresses: false` admit nothing of it.
#[test]
fn ipv6_link_local_is_refused_in_every_class_unless_an_ip_entry_names_it() {
    let ll = ip("fe80::1");
    let lax = Guard::from_config(&Destinations {
        block_private_addresses: false,
        allow: vec!["router.test".into()],
        allow_all_metadata: true,
        ..Destinations::default()
    })
    .unwrap();
    for class in [
        EGRESS_DEFAULT,
        EGRESS_PROVIDER,
        EGRESS_OPEN_WEB,
        EGRESS_LOOPBACK_ALLOWED,
        EGRESS_OPERATOR_INFRASTRUCTURE,
    ] {
        assert_eq!(
            verdict(lax.judge_answer("router.test", &[ll], class)),
            Some(DEST_METADATA),
            "class {class}"
        );
        assert_eq!(
            lax.judge_name("[fe80::1]", class).unwrap_err().verdict,
            DEST_METADATA,
            "class {class}"
        );
        assert_eq!(
            verdict(lax.judge_answer_with("router.test", &[ll], class, false, true)),
            Some(DEST_METADATA),
            "a private reach, class {class}"
        );
    }
    let listed = guard(true, &["fe80::/10"]);
    assert_eq!(
        listed.judge_answer("router.test", &[ll], EGRESS_OPERATOR_INFRASTRUCTURE),
        Ok(())
    );
    let carved = Guard::from_config(&Destinations {
        legacy_allow: vec!["fe80::1".into()],
        ..Destinations::default()
    })
    .unwrap();
    assert_eq!(
        carved.judge_answer("router.test", &[ll], EGRESS_PROVIDER),
        Ok(())
    );
    assert_eq!(
        verdict(carved.judge_answer("router.test", &[ll], EGRESS_DEFAULT)),
        Some(DEST_METADATA)
    );
}
