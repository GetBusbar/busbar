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
#[test]
fn a_private_answer_is_refused_by_default() {
    let g = Guard::default();
    for a in [
        "\x310.0.0.5",
        "127.0.0.1",
        "\x3192.168.1.1",
        "\x3100.64.0.1",
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
#[test]
fn the_allowlist_admits_a_private_answer() {
    let g = guard(
        true,
        &[
            "Ollama.Internal.",
            "*.corp.example",
            "\x310.0.0.0/8",
            "fd00:1::/32",
        ],
    );
    assert_eq!(
        g.judge_answer("ollama.internal", &[ip("\x310.9.9.9")], C),
        Ok(())
    );
    assert_eq!(
        g.judge_answer("db.corp.example", &[ip("\x3192.168.1.1")], C),
        Ok(())
    );
    assert_eq!(
        g.judge_answer("a.b.corp.example", &[ip("\x3192.168.1.1")], C),
        Ok(())
    );
    assert_eq!(g.judge_answer("x.test", &[ip("\x310.1.2.3")], C), Ok(()));
    assert_eq!(
        g.judge_answer("x.test", &[ip("::ffff:\x310.1.2.3")], C),
        Ok(())
    );
    assert_eq!(g.judge_answer("x.test", &[ip("fd00:1::5")], C), Ok(()));

    for host in ["corp.example", "xcorp.example"] {
        assert_eq!(
            verdict(g.judge_answer(host, &[ip("\x3192.168.1.1")], C)),
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

/// A guard over `allow` as the judge would hold it if a boot refusal were ever missed: each entry
/// parsed, but the boot refusal of a metadata entry ([`refuse_metadata_entry`]) skipped, so the dial
/// arm is pinned on its own (defence in depth).
fn unchecked(allow: &[&str]) -> Guard {
    Guard {
        allow: allow
            .iter()
            .enumerate()
            .map(|(i, e)| entry(i, e).expect("a well-formed entry"))
            .collect(),
        ..Guard::default()
    }
}

const EVERY_CLASS: [u32; 5] = [
    EGRESS_DEFAULT,
    EGRESS_PROVIDER,
    EGRESS_OPEN_WEB,
    EGRESS_LOOPBACK_ALLOWED,
    EGRESS_OPERATOR_INFRASTRUCTURE,
];

/// T-G1: no allowlist entry admits a metadata answer, a host entry or an exact IP entry naming the
/// metadata address itself, in any class.
#[test]
fn a_name_entry_never_admits_a_metadata_answer() {
    let g = guard(true, &["evil.test"]);
    assert_eq!(
        verdict(g.judge_answer("evil.test", &[ip("169.254.169.254")], C)),
        Some(DEST_METADATA)
    );
    let g = unchecked(&["169.254.169.254"]);
    for class in EVERY_CLASS {
        assert_eq!(
            verdict(g.judge_answer("evil.test", &[ip("169.254.169.254")], class)),
            Some(DEST_METADATA),
            "class {class}"
        );
    }
}

/// T-G2: a metadata NAME in the allowlist never lifts the name arm's refusal, in any class.
#[test]
fn a_metadata_name_entry_is_refused_in_every_class() {
    let g = unchecked(&["metadata.google.internal"]);
    for class in EVERY_CLASS {
        assert_eq!(
            g.judge_name("metadata.google.internal", class)
                .unwrap_err()
                .verdict,
            DEST_METADATA,
            "class {class}"
        );
    }
}

/// BUSBAR-3134: an `advanced.allow_destinations` entry that names a cloud-metadata destination (a
/// metadata host name, a metadata literal, or a /32 or /128 equal to a metadata address) refuses the
/// boot, naming the index; a wider network that merely covers metadata loads (it never admits it).
#[test]
fn an_allow_entry_naming_metadata_is_refused_at_boot() {
    let refused = |e: &str| {
        Guard::from_config(&Destinations {
            allow: vec!["ok.test".into(), e.into()],
            ..Destinations::default()
        })
        .unwrap_err()
    };
    for named in [
        "169.254.169.254",
        "169.254.169.254/32",
        "169.254.170.2",
        "\x3100.100.100.200",
        "168.63.129.16/32",
        "fd00:ec2::254",
        "[fd00:ec2::254]",
        "fd00:ec2::254/128",
        "fd00:ec2::23/128",
        "::ffff:169.254.169.254",
        "fe80::1",
        "metadata.google.internal",
        "METADATA.Google.Internal.",
        "instance-data",
    ] {
        let r = refused(named);
        assert!(
            r.starts_with("advanced.allow_destinations[1]: `"),
            "{named}: {r}"
        );
        assert!(
            r.contains("names a cloud-metadata destination") && r.contains("BUSBAR-3134"),
            "{named}: {r}"
        );
    }
    for wider in [
        "169.254.0.0/16",
        "169.254.169.0/24",
        "\x3100.100.100.200/31",
        "fd00:ec2::254/127",
        "fe80::/10",
        "0.0.0.0/0",
        "*.google.internal",
    ] {
        assert!(
            Guard::from_config(&Destinations {
                allow: vec![wider.into()],
                ..Destinations::default()
            })
            .is_ok(),
            "{wider} covers metadata but does not name it"
        );
    }
}

/// A cidr allowlist entry does not admit a metadata address inside it.
#[test]
fn a_cidr_allowlist_entry_does_not_admit_a_metadata_address_inside_it() {
    for (entry, meta, private) in [
        (
            "\x3100.64.0.0/10",
            "\x3100.100.100.200",
            Some("\x3100.64.0.1"),
        ),
        ("169.254.0.0/16", "169.254.169.254", None),
        ("169.254.0.0/16", "169.254.170.2", None),
        ("169.254.0.0/16", "::ffff:169.254.169.254", None),
        ("0.0.0.0/0", "168.63.129.16", Some("\x310.0.0.5")),
        ("192.0.0.0/24", "192.0.0.192", None),
        ("fd00::/8", "fd00:ec2::254", Some("fd12::1")),
        ("fd00:ec2::/32", "fd00:ec2::23", None),
    ] {
        for block in [true, false] {
            let g = guard(block, &[entry]);
            for class in [
                EGRESS_DEFAULT,
                EGRESS_PROVIDER,
                EGRESS_OPEN_WEB,
                EGRESS_LOOPBACK_ALLOWED,
                EGRESS_OPERATOR_INFRASTRUCTURE,
            ] {
                let r = g.judge_answer("svc.test", &[ip(meta)], class).unwrap_err();
                assert_eq!(
                    (r.verdict, r.addr),
                    (DEST_METADATA, Some(ip(meta))),
                    "{entry} {meta} class {class} block {block}"
                );
                assert_eq!(
                    r.to_string(),
                    format!(
                        "host `svc.test` resolves to the cloud-metadata address {}; that is \
                         refused unconditionally",
                        ip(meta)
                    )
                );
                let literal = if meta.contains(':') {
                    format!("[{meta}]")
                } else {
                    meta.to_owned()
                };
                assert_eq!(
                    g.judge_name(&literal, class).unwrap_err().verdict,
                    DEST_METADATA,
                    "{entry} literal {literal} class {class} block {block}"
                );
                assert_eq!(
                    verdict(g.judge_answer_with("svc.test", &[ip(meta)], class, true, true)),
                    Some(DEST_METADATA),
                    "{entry} {meta} strict, reach, class {class}"
                );
                if let Some(p) = private {
                    assert_eq!(
                        g.judge_answer("svc.test", &[ip(p)], class),
                        Ok(()),
                        "{entry} still admits {p}, class {class}"
                    );
                }
            }
        }
    }

    let g = Guard::from_config(&Destinations {
        allow: vec!["203.0.113.0/24".into()],
        blocked: vec!["203.0.113.9".into()],
        ..Destinations::default()
    })
    .unwrap();
    assert_eq!(
        verdict(g.judge_answer("x.test", &[ip("203.0.113.9")], C)),
        Some(DEST_METADATA)
    );
    assert_eq!(g.judge_answer("x.test", &[ip("203.0.113.8")], C), Ok(()));
}

/// An exact metadata allow entry is NOT a carve-out (it is refused at boot, BUSBAR-3134); even a
/// guard that somehow held one refuses the metadata answer in the default, provider and
/// operator-infrastructure classes, and a wider network never names it.
#[test]
fn an_exact_metadata_allow_entry_admits_nothing() {
    for (entry, meta) in [
        ("\x3100.100.100.200", "\x3100.100.100.200"),
        ("\x3100.100.100.200/32", "\x3100.100.100.200"),
        ("169.254.169.254/32", "169.254.169.254"),
        ("169.254.169.254", "::ffff:169.254.169.254"),
        ("fd00:ec2::254", "fd00:ec2::254"),
        ("fd00:ec2::254/128", "fd00:ec2::254"),
        ("fd00:ec2::23/128", "fd00:ec2::23"),
    ] {
        let g = unchecked(&[entry]);
        for class in [C, EGRESS_PROVIDER, EGRESS_OPERATOR_INFRASTRUCTURE] {
            assert_eq!(
                verdict(g.judge_answer("svc.test", &[ip(meta)], class)),
                Some(DEST_METADATA),
                "{entry} refuses {meta}, class {class}"
            );
        }
    }
    for wider in [
        "\x3100.100.100.200/31",
        "169.254.169.0/24",
        "fd00:ec2::254/127",
    ] {
        let g = guard(true, &[wider]);
        let meta = if wider.contains(':') {
            "fd00:ec2::254"
        } else if wider.starts_with("100.") {
            "\x3100.100.100.200"
        } else {
            "169.254.169.254"
        };
        assert_eq!(
            verdict(g.judge_answer("svc.test", &[ip(meta)], C)),
            Some(DEST_METADATA),
            "{wider} does not name {meta}"
        );
    }
}

/// RED `block_private_addresses: false` admits private answers and names, never cloud metadata.
#[test]
fn block_false_admits_private_but_not_metadata() {
    let g = guard(false, &[]);
    assert_eq!(g.judge_answer("db.test", &[ip("\x310.0.0.5")], C), Ok(()));
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

/// `security.blocked_metadata_hosts`, the 1.5.5 key that still loads, extends the refusal: a listed
/// name or address is refused as cloud metadata in every class, and no allowlist entry lifts it.
#[test]
fn the_extra_metadata_refusals_hold_in_every_class() {
    let g = Guard::from_config(&Destinations {
        block_private_addresses: true,
        allow: vec!["imds.corp.example".into(), "203.0.113.0/24".into()],
        blocked: vec!["imds.corp.example".into(), "203.0.113.9".into()],
    })
    .unwrap();
    for class in EVERY_CLASS {
        assert_eq!(
            g.judge_name("imds.corp.example", class)
                .unwrap_err()
                .verdict,
            DEST_METADATA,
            "class {class}"
        );
        assert_eq!(
            verdict(g.judge_answer("x.test", &[ip("203.0.113.9")], class)),
            Some(DEST_METADATA),
            "class {class}"
        );
    }
}

/// A config commit re-publishes the extra refusals to every clone of the guard: a refusal the
/// commit adds holds at once, and one it drops is lifted.
#[test]
fn a_commit_republishes_the_metadata_lists() {
    let blocking = Destinations {
        block_private_addresses: true,
        blocked: vec!["93.184.216.34".into()],
        ..Destinations::default()
    };
    let g = Guard::from_config(&Destinations {
        block_private_addresses: true,
        ..Destinations::default()
    })
    .unwrap();
    let held = g.clone();
    // A public address: 203.0.113.0/24 is documentation space, which the guard already refuses as
    // internal, so it could not show a lifted refusal.
    let listed = [ip("93.184.216.34")];
    assert_eq!(
        held.judge_answer("x.test", &listed, EGRESS_PROVIDER),
        Ok(())
    );
    g.publish(&blocking);
    assert_eq!(
        verdict(held.judge_answer("x.test", &listed, EGRESS_PROVIDER)),
        Some(DEST_METADATA)
    );
    g.publish(&Destinations {
        block_private_addresses: true,
        ..Destinations::default()
    });
    assert_eq!(
        held.judge_answer("x.test", &listed, EGRESS_PROVIDER),
        Ok(())
    );
}

/// A bad allowlist entry refuses the boot, naming the key, its index and the entry (userinfo
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
        "\x310.0.0.0/33",
        "*corp.example",
    ] {
        assert!(
            refused(bad).starts_with("advanced.allow_destinations[1]: "),
            "{bad}"
        );
    }
    assert!(refused("\x310.0.0.1/8").contains("past its prefix length"));
}

/// THE DEFAULT POLICY is one table: the provider class and a destination from request data (the
#[test]
fn private_is_refused_for_providers_and_request_data_and_allowed_for_operator_infrastructure() {
    let g = Guard::default();
    for class in PRIVATE_REFUSED_IN {
        assert_eq!(
            verdict(g.judge_answer("db.test", &[ip("\x310.0.0.5")], *class)),
            Some(DEST_INTERNAL)
        );
    }
    assert!(PRIVATE_REFUSED_IN.contains(&EGRESS_PROVIDER));
    assert_eq!(
        g.judge_answer(
            "db.test",
            &[ip("\x310.0.0.5")],
            EGRESS_OPERATOR_INFRASTRUCTURE
        ),
        Ok(())
    );
    assert_eq!(
        verdict(g.judge_answer("db.test", &[ip("\x310.0.0.5")], EGRESS_LOOPBACK_ALLOWED)),
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

/// A provider dial with no allowlist entry for it is refused a private or loopback address, by
#[test]
fn a_provider_dial_is_refused_a_private_address_unless_allowlisted() {
    let strict = Guard::default();
    let p = EGRESS_PROVIDER;
    assert_eq!(
        verdict(strict.judge_answer("model.internal", &[ip("\x310.0.0.5")], p)),
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
        allowed.judge_answer("model.internal", &[ip("\x310.0.0.5")], p),
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
}

/// THE DESIGN §5 egress-class table, held beside the provider fix above: operator infrastructure is
#[test]
fn operator_infrastructure_is_allowed_private_and_refused_metadata_whatever_is_carved() {
    let oi = EGRESS_OPERATOR_INFRASTRUCTURE;
    let strict = Guard::default();
    assert_eq!(
        strict.judge_answer("db.test", &[ip("\x310.0.0.5")], oi),
        Ok(())
    );
    assert_eq!(
        strict.judge_name("127.0.0.1", oi),
        Ok(Some(ip("127.0.0.1")))
    );
    let carved = Guard::from_config(&Destinations {
        block_private_addresses: true,
        allow: vec!["db.test".into()],
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

/// A lookup past the cap is refused at once and starts no thread.
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
    rest.sort();
    assert_eq!(rest, [(0, true), (1, true)], "the two in flight answer");
}

/// A CONFIGURED OPEN-WEB TARGET KEEPS THE OPEN-WEB CLASS ("a
#[test]
fn a_configured_open_web_target_keeps_its_class_and_is_refused_a_private_address() {
    assert_eq!(judged_class(EGRESS_OPEN_WEB, true), EGRESS_OPEN_WEB);
    assert_eq!(
        judged_class(EGRESS_DEFAULT, true),
        EGRESS_OPERATOR_INFRASTRUCTURE
    );
    let g = Guard::default();
    for a in ["127.0.0.1", "\x310.0.0.7"] {
        assert_eq!(
            verdict(g.judge_answer(a, &[ip(a)], judged_class(EGRESS_OPEN_WEB, true))),
            Some(DEST_INTERNAL),
            "a configured webhook to {a}"
        );
    }
}

/// The odd spellings of the SSRF guard bypass (HIGH, a plugin argument guard's hosts reach
const ODD_SPELLINGS: [(&str, &str); 6] = [
    (
        "\u{ff4c}\u{ff4f}\u{ff43}\u{ff41}\u{ff4c}\u{ff48}\u{ff4f}\u{ff53}\u{ff54}",
        "localhost",
    ),
    ("\u{2460}\u{2461}\u{2466}.0.0.1", "127.0.0.1"),
    (
        "\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}.\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}",
        "169.254.169.254",
    ),
    ("LOCALHOST\u{3002}", "localhost"),
    ("\u{ff10}\u{ff58}\u{ff17}\u{ff46}\u{ff0e}\u{ff11}", "0x7f.1"),
    (
        "\u{ff10}\u{ff11}\u{ff17}\u{ff17}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff11}",
        "017700000001",
    ),
];

/// A name judgement as a verdict and the address that decided it, the refused host's own spelling
type NameVerdict = Result<Option<IpAddr>, (u64, Option<IpAddr>)>;

fn judged(r: Result<Option<IpAddr>, Refusal>) -> NameVerdict {
    r.map_err(|r| (r.verdict, r.addr))
}

/// RED, the SSRF guard bypass: every odd spelling is judged exactly as the plain ASCII host
#[test]
fn an_odd_spelling_is_judged_as_the_ascii_host_it_maps_to() {
    let g = Guard::default();
    for class in [
        EGRESS_DEFAULT,
        EGRESS_PROVIDER,
        EGRESS_OPEN_WEB,
        EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_LOOPBACK_ALLOWED,
    ] {
        for strict in [false, true] {
            for (odd, plain) in ODD_SPELLINGS {
                assert_eq!(
                    judged(g.judge_name_as(odd, class, strict)),
                    judged(g.judge_name_as(plain, class, strict)),
                    "`{odd}` beside `{plain}`, class {class}, strict {strict}"
                );
            }
        }
    }

    let refused = |h: &str| g.judge_name(h, C).err().map(|r| (r.verdict, r.addr));
    let lo = Some(ip("127.0.0.1"));
    let want = [
        Some((DEST_INTERNAL, None)),
        Some((DEST_INTERNAL, lo)),
        Some((DEST_METADATA, Some(ip("169.254.169.254")))),
        Some((DEST_INTERNAL, None)),
        Some((DEST_OBFUSCATED, None)),
        Some((DEST_OBFUSCATED, None)),
    ];
    for (&(odd, plain), want) in ODD_SPELLINGS.iter().zip(want) {
        assert_eq!(refused(odd), want, "{odd}");
        assert_eq!(refused(plain), want, "{plain}");
    }

    for spelling in ["0x7f.1", "017700000001"] {
        assert_eq!(
            g.judge_name_as(spelling, EGRESS_LOOPBACK_ALLOWED, false),
            Ok(Some(ip("127.0.0.1"))),
            "{spelling}"
        );
    }
}

/// RED: a host the mapping reads as nothing is refused as unjudgeable (`DEST_NO_HOST`), naming the
#[test]
fn a_host_that_maps_to_nothing_is_refused_as_unjudgeable() {
    let g = guard(true, &["0x"]);
    for host in ["b\u{fc}cher\u{ff1c}.example", "0x", "1.0x", "0x.0x.0x.0x"] {
        for class in [EGRESS_DEFAULT, EGRESS_OPERATOR_INFRASTRUCTURE] {
            let refusal = g.judge_name(host, class).expect_err(host);
            assert_eq!(
                (refusal.verdict, refusal.addr),
                (DEST_NO_HOST, None),
                "{host}"
            );
            assert_eq!(refusal.host, host);
            let said = refusal.to_string();
            assert!(
                said.starts_with(&format!("host `{host}` cannot be judged")),
                "{said}"
            );
        }
        let answered = g.judge_answer(host, &[ip("93.184.216.34")], C);
        assert_eq!(verdict(answered), Some(DEST_NO_HOST), "{host}");
        assert!(!names_loopback(host), "{host}");
    }
}

/// The operator's lists compare in the mapped form too: a `blocked_metadata_hosts` entry refuses
#[test]
fn the_configured_lists_compare_in_the_mapped_form() {
    let full_width_meta = "\u{ff4d}\u{ff45}\u{ff54}\u{ff41}.example";
    for (entry, target) in [
        ("meta.example", full_width_meta),
        (full_width_meta, "meta.example"),
        ("META.example.", "meta.example"),
    ] {
        let g = Guard::from_config(&Destinations {
            block_private_addresses: true,
            blocked: vec![entry.to_owned()],
            ..Destinations::default()
        })
        .expect("a guard");
        assert_eq!(
            verdict(g.judge_name(target, C).map(|_| ())),
            Some(DEST_METADATA),
            "entry `{entry}`, target `{target}`"
        );
    }
    let g = guard(true, &["xn--bcher-kva.example"]);
    for idn in ["b\u{fc}cher.example", "B\u{dc}CHER.example."] {
        assert_eq!(g.judge_name(idn, C), Ok(None), "{idn}");
        assert_eq!(
            g.judge_answer(idn, &[ip("\x310.0.0.5")], C),
            Ok(()),
            "{idn}"
        );
    }
}

/// GREEN control: a public IDN name maps to its punycode name and is admitted, as the plain name
#[test]
fn a_public_idn_name_maps_to_punycode_and_is_allowed() {
    let g = Guard::default();
    for idn in ["b\u{fc}cher.example", "xn--bcher-kva.example"] {
        assert_eq!(g.judge_name(idn, C), Ok(None), "{idn}");
        assert_eq!(
            g.judge_answer(idn, &[ip("93.184.216.34")], C),
            Ok(()),
            "{idn}"
        );
        assert_eq!(
            verdict(g.judge_answer(idn, &[ip("\x310.0.0.5")], C)),
            Some(DEST_INTERNAL),
            "{idn}"
        );
    }
}

/// An IPv6 literal in brackets, with a zone id, and an ASCII host are judged as before, byte for
#[test]
fn bracketed_zoned_and_ascii_hosts_are_judged_as_before() {
    let g = Guard::default();
    for (host, want) in [
        ("[::1]", Err((DEST_INTERNAL, Some(ip("::1"))))),
        (
            "[fe80::1%25eth0]",
            Err((DEST_METADATA, Some(ip("fe80::1")))),
        ),
        ("fe80::1%eth0", Err((DEST_METADATA, Some(ip("fe80::1"))))),
        (
            "[::ffff:169.254.169.254]",
            Err((DEST_METADATA, Some(ip("::ffff:169.254.169.254")))),
        ),
        ("Api.Example.COM.", Ok(None)),
        ("LOCALHOST.", Err((DEST_INTERNAL, None))),
        ("0x7f000001", Err((DEST_OBFUSCATED, None))),
        ("08", Err((DEST_OBFUSCATED, None))),
        ("[2606:4700::1111]", Ok(Some(ip("2606:4700::1111")))),
    ] {
        assert_eq!(judged(g.judge_name(host, C)), want, "{host}");
    }
}

/// RED, the percent-escape the guard did not decode: a host holding a `%` outside an IPv6
#[test]
fn a_percent_escape_outside_a_zone_id_is_refused_as_unjudgeable() {
    let g = guard(true, &["*.example", "127.0.0.0/8"]);
    for host in [
        "%6c%6fcalhost",
        "%6C%6FCALHOST.",
        "%31%32%37.0.0.1",
        "%31%36%39.254.169.254",
        "api%2eexample",
        "a%2e.example",
    ] {
        for class in [
            EGRESS_DEFAULT,
            EGRESS_OPERATOR_INFRASTRUCTURE,
            EGRESS_PROVIDER,
        ] {
            let refusal = g.judge_name(host, class).expect_err(host);
            assert_eq!(
                (refusal.verdict, refusal.addr),
                (DEST_NO_HOST, None),
                "{host}"
            );
            assert_eq!(refusal.host, host);
            assert!(
                refusal
                    .to_string()
                    .starts_with(&format!("host `{host}` cannot be judged")),
                "{refusal}"
            );
        }
        assert_eq!(
            verdict(g.judge_answer(host, &[ip("93.184.216.34")], C)),
            Some(DEST_NO_HOST),
            "{host}"
        );
        assert!(!names_loopback(host), "{host}");
    }

    for zoned in ["[fe80::1%25eth0]", "fe80::1%eth0"] {
        assert_eq!(
            judged(g.judge_name(zoned, C)),
            Err((DEST_METADATA, Some(ip("fe80::1")))),
            "{zoned}"
        );
    }
}

/// The guard, the one metadata and link-local refusal a judged dial meets, refuses an IPv6
#[test]
fn ipv6_link_local_is_refused_in_every_class_whatever_is_listed() {
    let ll = ip("fe80::1");
    let lax = Guard::from_config(&Destinations {
        block_private_addresses: false,
        allow: vec!["router.test".into()],
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
        verdict(listed.judge_answer("router.test", &[ll], EGRESS_OPERATOR_INFRASTRUCTURE)),
        Some(DEST_METADATA),
        "a network covering link-local never admits it"
    );
    let named = unchecked(&["fe80::1"]);
    for class in EVERY_CLASS {
        assert_eq!(
            verdict(named.judge_answer("router.test", &[ll], class)),
            Some(DEST_METADATA),
            "an exact link-local entry admits nothing, class {class}"
        );
    }
}

/// THE ONE POLICY, BY THE CLASS EACH FEATURE PLUGIN DIALS UNDER (plane-mcp and plane-a2a:
/// `provider`; export-otlp and hook-webrequest: `loopback-allowed`; export-webhook and auth-oidc's
/// documents: `open-web`; a need naming no configured target: `default`). In every one a private
/// answer, IPv6 site-local included, is refused by default; `advanced.allow_destinations` admits
/// it by host, address or network; cloud metadata stays refused even when a name or network
/// entry covers it.
#[test]
fn every_feature_plugin_class_is_governed_by_the_one_allowlist() {
    let classes = [
        EGRESS_PROVIDER,
        EGRESS_LOOPBACK_ALLOWED,
        EGRESS_OPEN_WEB,
        EGRESS_DEFAULT,
    ];
    let strict = Guard::default();
    let listed = guard(
        true,
        &[
            "collector.internal",
            "\x310.2.3.4",
            "fec0::/10",
            "169.254.0.0/16",
        ],
    );
    for class in classes {
        for (host, addr) in [
            ("collector.internal", "\x310.9.9.9"),
            ("mcp.internal", "\x310.2.3.4"),
            ("old.internal", "fec0::7"),
        ] {
            assert_eq!(
                verdict(strict.judge_answer(host, &[ip(addr)], class)),
                Some(DEST_INTERNAL),
                "default refuses {host} -> {addr} in class {class}"
            );
            assert_eq!(
                listed.judge_answer(host, &[ip(addr)], class),
                Ok(()),
                "the allowlist admits {host} -> {addr} in class {class}"
            );
        }
        assert_eq!(
            verdict(listed.judge_answer("collector.internal", &[ip("169.254.169.254")], class)),
            Some(DEST_METADATA),
            "a host entry never admits a metadata answer, class {class}"
        );
        assert_eq!(
            verdict(listed.judge_answer("svc.test", &[ip("169.254.169.254")], class)),
            Some(DEST_METADATA),
            "a network entry covering metadata never admits it, class {class}"
        );
        assert_eq!(
            verdict(listed.judge_answer("svc.test", &[ip("fd00:ec2::254")], class)),
            Some(DEST_METADATA),
            "the v6 metadata address stays refused, class {class}"
        );
    }
}

fn sock(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// IF 12.1, the node's own ports: a Need dial (`all_classes`) to the node's own listen port on
/// loopback, the unspecified address or a bound address is refused in every class; any other port,
/// and any other address, is not.
#[test]
fn a_need_dial_never_reaches_the_nodes_own_ports() {
    let g = Guard::default();
    g.publish_own(&[8080, 9090], &[ip("10.0.0.5")]);
    for class in EVERY_CLASS {
        for own in [
            "127.0.0.1:8080",
            "[::1]:9090",
            "0.0.0.0:8080",
            "10.0.0.5:9090",
        ] {
            assert_eq!(
                verdict(g.not_the_node(class, sock(own), true)),
                Some(DEST_INTERNAL),
                "{own} in class {class}"
            );
        }
        for other in ["127.0.0.1:8081", "10.0.0.6:8080", "93.184.216.34:8080"] {
            assert_eq!(
                g.not_the_node(class, sock(other), true),
                Ok(()),
                "{other} in class {class}"
            );
        }
    }
}

/// Core's own upstream exchanges and push deliveries keep today's scope: the loopback-allowed
/// class only.
#[test]
fn the_narrow_scope_judges_the_loopback_allowed_class_only() {
    let g = Guard::default();
    g.publish_own(&[8080], &[]);
    let own = sock("127.0.0.1:8080");
    assert_eq!(
        verdict(g.not_the_node(EGRESS_LOOPBACK_ALLOWED, own, false)),
        Some(DEST_INTERNAL)
    );
    for class in [EGRESS_DEFAULT, EGRESS_PROVIDER, EGRESS_OPEN_WEB] {
        assert_eq!(g.not_the_node(class, own, false), Ok(()), "class {class}");
    }
}

/// The published set is replaced whole and every clone reads the set in force now.
#[test]
fn a_republished_own_set_is_seen_by_every_clone() {
    let g = Guard::default();
    let clone = g.clone();
    let own = sock("127.0.0.1:8080");
    assert_eq!(
        clone.not_the_node(C, own, true),
        Ok(()),
        "nothing published"
    );
    g.publish_own(&[8080], &[]);
    assert_eq!(
        verdict(clone.not_the_node(C, own, true)),
        Some(DEST_INTERNAL)
    );
    g.publish_own(&[9000], &[]);
    assert_eq!(
        clone.not_the_node(C, own, true),
        Ok(()),
        "the old set is gone"
    );
}

/// A DNS answer carrying a tunnel must receive the same refusal as its embedded IPv4.
#[test]
fn tunnel_dns_answers_keep_metadata_and_private_refusals_distinct() {
    let guard = Guard::default();
    for (literal, expected) in [
        ("2002:a9fe:a9fe::", Some(DEST_METADATA)),
        ("2002:7f00:1::", Some(DEST_INTERNAL)),
        ("2002:a01:203::", Some(DEST_INTERNAL)),
        ("2002:808:808::", None),
        ("2001:0:4136:e378:8000:63bf:5601:5601", Some(DEST_METADATA)),
        ("2001:0:4136:e378:8000:63bf:80ff:fffe", Some(DEST_INTERNAL)),
        ("2001:0:4136:e378:8000:63bf:f5fe:fdfc", Some(DEST_INTERNAL)),
        ("2001:0:4136:e378:8000:63bf:f7f7:f7f7", None),
    ] {
        let addr = ip(literal);
        let result = guard.judge_answer("svc.test", &[addr], C);
        match expected {
            Some(verdict) => assert_eq!(
                result,
                Err(Refusal {
                    verdict,
                    host: "svc.test".into(),
                    addr: Some(addr),
                }),
                "{literal}"
            ),
            None => assert_eq!(result, Ok(()), "{literal}"),
        }
    }
}

/// Admission provenance cannot relax the runtime provider destination guard.
#[test]
fn provider_and_default_keep_identical_private_and_metadata_refusals() {
    let g = Guard::default();
    for class in [EGRESS_DEFAULT, EGRESS_PROVIDER] {
        for address in ["10.0.0.7", "127.0.0.1", "fd12::1"] {
            assert_eq!(
                verdict(g.judge_answer("backend.test", &[ip(address)], class)),
                Some(DEST_INTERNAL)
            );
        }
        assert_eq!(
            verdict(g.judge_answer("backend.test", &[ip("169.254.169.254")], class)),
            Some(DEST_METADATA)
        );
    }
}
