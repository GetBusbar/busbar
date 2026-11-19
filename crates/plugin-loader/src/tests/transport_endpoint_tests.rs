// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRANSPORT-SECURITY-POLICY §8 tests 1, 2, 3, 10 and 15 at the loader seam: the CHECK answer's ENDPOINT
//! records are decoded (`decode_endpoints`) and judged with `transport_verdict` (`judge_endpoints`) before any
//! `open`, whatever the kind. Neither function takes a kind, so one table of cases stands for the store, auth,
//! secret, export and hook fixtures alike (the rule-14 "no kind changes the verdict" arm lives here as the
//! absence of a kind parameter).

use super::*;
use busbar_plugin_abi::need::need_flag::{TLS_INBAND, TLS_MUTUAL, TLS_NONE, TLS_REQUIRED};
use busbar_plugin_abi::records::{Reply, Writer};

const VERIFIED: Accept = Accept(0);
const PLAINTEXT: Accept = Accept(Accept::PLAINTEXT);
const UNVERIFIED: Accept = Accept(Accept::UNVERIFIED_TLS);

fn ep(flags: u32, dest: &str) -> DeclaredEndpoint {
    DeclaredEndpoint {
        op: op::OPEN,
        flags,
        dest: dest.into(),
    }
}

/// The text of a CONFIG refusal; anything else (or an admission) fails the test.
fn config_text(r: Result<(), OpenError>) -> String {
    match r {
        Err(OpenError::Config { code, text, .. }) => {
            assert_eq!(code, refused::R_CONFIG);
            text
        }
        Err(_) => panic!("refused, but not as CONFIG"),
        Ok(()) => panic!("admitted"),
    }
}

fn answer(records: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut reply = Reply::new();
    for (op, flags, dest) in records {
        reply
            .put_pod_tail(
                tag::ENDPOINT,
                &EndpointRec {
                    op: *op,
                    flags: *flags,
                },
                dest,
            )
            .unwrap();
    }
    reply.as_bytes().to_vec()
}

fn decoded(records: &[(u32, u32, &[u8])]) -> Result<Vec<DeclaredEndpoint>, OpenError> {
    decode_endpoints(&answer(records), "store.main")
}

/// Test 1: a TLS_NONE endpoint refuses the check with BUSBAR-3160, the printed line included, before any open.
#[test]
fn transport_plaintext_refused_at_check() {
    let text = config_text(judge_endpoints(
        "store.main",
        "postgres",
        VERIFIED,
        &[ep(TLS_NONE, "db:5432")],
    ));
    assert!(
        text.starts_with(
            "BUSBAR-3160: store.main (module postgres) would connect to db:5432 without TLS (tcp, plaintext).\n\
             busbar 1.6.0 connects only over verified TLS, and nothing is exempt: not loopback, not unix sockets.\n"
        ),
        "{text}"
    );
    assert!(text.contains("outbound.tls.trust_anchors"), "{text}");
    assert!(text.contains("(match: db, verify: pin)"), "{text}");
    assert!(
        text.contains("Add this line to the store.main\n     block of your configuration"),
        "{text}"
    );
    assert!(
        text.contains(
            "insecure_transport: { accept: plaintext, reason: \"<why this is acceptable>\" }"
        ),
        "{text}"
    );
    assert!(
        text.ends_with(
            "See https://getbusbar.com/docs/1.6/errors/BUSBAR-3160 and docs/migration-1.6.md#transport-security"
        ),
        "{text}"
    );
    // Verified TLS, in any of its three forms, is admitted with no setting at all.
    for tls in [TLS_REQUIRED, TLS_MUTUAL, TLS_INBAND] {
        assert!(judge_endpoints("store.main", "postgres", VERIFIED, &[ep(tls, "db:5432")]).is_ok());
    }
}

/// Test 2: no loopback exemption. Every loopback spelling refuses exactly as test 1, and only `plaintext` admits it.
#[test]
fn transport_no_loopback_exemption() {
    for dest in ["127.0.0.1:5432", "[::1]:5432", "localhost:6379"] {
        let text = config_text(judge_endpoints(
            "auth.corp",
            "ldap",
            VERIFIED,
            &[ep(TLS_NONE, dest)],
        ));
        assert!(
            text.starts_with(&format!(
                "BUSBAR-3160: auth.corp (module ldap) would connect to {dest} without TLS (tcp, plaintext)."
            )),
            "{text}"
        );
        // An unverified-TLS acceptance does not admit plaintext; the plaintext one does.
        config_text(judge_endpoints(
            "auth.corp",
            "ldap",
            UNVERIFIED,
            &[ep(TLS_NONE, dest)],
        ));
        assert!(judge_endpoints("auth.corp", "ldap", PLAINTEXT, &[ep(TLS_NONE, dest)]).is_ok());
    }
    // The printed match names the host without its port or brackets' port.
    let text = config_text(judge_endpoints(
        "auth.corp",
        "ldap",
        VERIFIED,
        &[ep(TLS_NONE, "[::1]:5432")],
    ));
    assert!(text.contains("(match: [::1], verify: pin)"), "{text}");
}

/// Test 3: no unix exemption, for a store and a non-store instance alike (no kind reaches the verdict). A unix
/// socket carries no TLS, so even a TLS mode on it is refused without `accept: plaintext`.
#[test]
fn transport_no_unix_exemption() {
    for (name, module) in [("store.main", "valkey"), ("hooks.wr", "webrequest")] {
        for flags in [TLS_NONE, TLS_REQUIRED] {
            let text = config_text(judge_endpoints(
                name,
                module,
                VERIFIED,
                &[ep(flags, "unix:/run/valkey.sock")],
            ));
            assert!(
                text.starts_with(&format!(
                    "BUSBAR-3160: {name} (module {module}) would connect to unix:/run/valkey.sock without TLS (unix socket, plaintext)."
                )),
                "{text}"
            );
            assert!(judge_endpoints(
                name,
                module,
                PLAINTEXT,
                &[ep(flags, "unix:/run/valkey.sock")]
            )
            .is_ok());
        }
    }
}

/// Test 15 (check-time half): an instance that declares no endpoint keeps an acceptance, so its printed line
/// still pastes; an acceptance that none of its declared endpoints needs is BUSBAR-3163; each bit admits only
/// what it names.
#[test]
fn transport_undeclared_acceptance_kept() {
    for accept in [VERIFIED, PLAINTEXT, UNVERIFIED, Accept(3)] {
        assert!(judge_endpoints("export.x", "otlp", accept, &[]).is_ok());
    }
    let text = config_text(judge_endpoints(
        "export.x",
        "otlp",
        PLAINTEXT,
        &[ep(TLS_REQUIRED, "collector:4318")],
    ));
    assert!(
        text.starts_with("BUSBAR-3163: export.x (module otlp) sets insecure_transport"),
        "{text}"
    );
    // unverified_tls over a TLS_INBAND upgrade is used; over a plaintext-only instance it is unused AND plaintext is refused.
    assert!(judge_endpoints(
        "store.main",
        "postgres",
        UNVERIFIED,
        &[ep(TLS_INBAND, "db:5432")]
    )
    .is_ok());
    config_text(judge_endpoints(
        "store.main",
        "postgres",
        UNVERIFIED,
        &[ep(TLS_NONE, "db:5432")],
    ));
    // Both bits over one TLS and one plaintext endpoint: both are used.
    assert!(judge_endpoints(
        "store.main",
        "postgres",
        Accept(3),
        &[ep(TLS_INBAND, "a:1"), ep(TLS_NONE, "b:2")]
    )
    .is_ok());
}

/// A refused request list, named by what is wrong with it.
type BadCase<'a> = (&'a str, Vec<(u32, u32, &'a [u8])>);

/// Test 10: the ENDPOINT records decode in answer order; more than 16, an over-long dest, an unknown op, an
/// egress class above 4, the retired bit 0x200, any stray flag bit or a dest that is not UTF-8 is INVALID, which
/// refuses CONFIG naming the instance.
#[test]
fn endpoint_record_decode() {
    let ok = decoded(&[
        (
            op::OPEN,
            TLS_INBAND | (egress::OPERATOR_INFRASTRUCTURE << 16),
            b"db:5432",
        ),
        (op::FETCH, TLS_REQUIRED, b"https://vault:8200/"),
    ])
    .unwrap();
    assert_eq!(
        ok,
        [
            ep(
                TLS_INBAND | (egress::OPERATOR_INFRASTRUCTURE << 16),
                "db:5432"
            ),
            DeclaredEndpoint {
                op: op::FETCH,
                flags: TLS_REQUIRED,
                dest: "https://vault:8200/".into()
            }
        ]
    );
    assert!(decoded(&[]).unwrap().is_empty());
    let sixteen: Vec<(u32, u32, &[u8])> = (0..16)
        .map(|_| (op::OPEN, TLS_REQUIRED, &b"h:1"[..]))
        .collect();
    assert_eq!(decoded(&sixteen).unwrap().len(), 16);
    let seventeen: Vec<(u32, u32, &[u8])> = (0..17)
        .map(|_| (op::OPEN, TLS_REQUIRED, &b"h:1"[..]))
        .collect();
    let long = vec![b'a'; 2_049];
    let max = vec![b'a'; 2_048];
    assert!(decoded(&[(op::OPEN, TLS_REQUIRED, &max[..])]).is_ok());
    let bad: [BadCase<'_>; 7] = [
        ("more than 16", seventeen),
        (
            "dest over 2,048 bytes",
            vec![(op::OPEN, TLS_REQUIRED, &long[..])],
        ),
        ("op", vec![(0xdead, TLS_REQUIRED, &b"h:1"[..])]),
        (
            "flags",
            vec![(op::OPEN, TLS_REQUIRED | (5 << 16), &b"h:1"[..])],
        ),
        ("flags", vec![(op::OPEN, TLS_REQUIRED | 0x200, &b"h:1"[..])]),
        (
            "flags",
            vec![(op::OPEN, TLS_REQUIRED | 0x4000_0000, &b"h:1"[..])],
        ),
        (
            "dest not UTF-8",
            vec![(op::OPEN, TLS_REQUIRED, &[0xffu8, 0xfe][..])],
        ),
    ];
    for (why, records) in bad {
        let text = config_text(decoded(&records).map(drop));
        assert!(
            text.starts_with("store.main: the plugin declared an invalid ENDPOINT (")
                && text.contains(why),
            "{why}: {text}"
        );
    }
}
