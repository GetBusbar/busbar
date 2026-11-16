// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NEED-DECODE (ABI-MIN3-INTERFACE §14): Every row of the §10.3 decode table, both ways (rounds 28, 29), plus
//! the ENDPOINT rows (TRANSPORT-SECURITY-POLICY §8 test 10).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! Moved to the owner's crate (the loader's ENDPOINT decode is private to it and is not widened for a test,
//! SDK-SAFE-TEST-HOST):
//!
//! - TEST-VALUE `bad_endpoint_records_are_invalid`:
//!   `busbar_plugin_loader::instance::endpoint_decode_tests::bad_endpoint_records_are_invalid` (more than 16, a
//!   dest over 2,048 bytes or not UTF-8, an op other than OPEN/FETCH, egress 5..=15, bit 0x200 or any stray bit
//!   is INVALID and refuses CONFIG naming the instance; 16 and 2,048 bytes decode, in answer order).

use busbar_plugin_abi::host::{decode_need, DirNeed, Need, NeedErr, RecordNeed, TlsMode};
use busbar_plugin_abi::need::{dir, need_flag as nf, op};
use busbar_plugin_abi::records::{tag, Reply, Writer};

/// A NEED body by hand (IF §6.1): NeedRec (op, flags, a, b, secret, trust, lens) then the four arguments.
fn need(op: u32, flags: u32, a: u64, b: u64, secret: u32, trust: u32, args: [&[u8]; 4]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&op.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&a.to_ne_bytes());
    bytes.extend_from_slice(&b.to_ne_bytes());
    bytes.extend_from_slice(&secret.to_ne_bytes());
    bytes.extend_from_slice(&trust.to_ne_bytes());
    for arg in args {
        bytes.extend_from_slice(&u32::try_from(arg.len()).expect("small").to_ne_bytes());
    }
    for arg in args {
        bytes.extend_from_slice(arg);
    }
    bytes
}

const E: &[u8] = &[];
const DEST: &[u8] = b"db.internal:5432";

fn invalid(body: &[u8], why: &str) {
    assert!(
        matches!(decode_need(body), Err(NeedErr::Invalid)),
        "{why}: must be INVALID"
    );
}

/// Nested records (PAIR, DM_*) for list arguments.
fn nested(build: impl FnOnce(&mut Reply)) -> Vec<u8> {
    let mut r = Reply::new();
    build(&mut r);
    r.as_bytes().to_vec()
}

/// One DIRECTORY flags word.
fn dflags(code: u32, kind: u32, apply: u32, state: u32, pull: bool) -> u32 {
    code | (kind << dir::KIND_SHIFT)
        | (apply << dir::APPLY_SHIFT)
        | (state << dir::STATE_SHIFT)
        | if pull { dir::PULL } else { 0 }
}

#[test]
fn every_decode_table_row_both_ways() {
    // OPEN: m → TlsMode, c → egress (0..=4).
    let egress = 3 << nf::EGRESS_SHIFT;
    match decode_need(&need(op::OPEN, nf::TLS_NONE, 0, 0, 0, 0, [DEST, E, E, E])) {
        Ok(Need::Open(n)) => {
            assert!(n.dest == "db.internal:5432" && matches!(n.tls, TlsMode::None) && n.egress == 0)
        }
        _ => panic!("OPEN NONE"),
    }
    match decode_need(&need(
        op::OPEN,
        nf::TLS_REQUIRED | egress,
        0,
        0,
        0,
        7,
        [DEST, b"db", b"h2,http/1.1", E],
    )) {
        Ok(Need::Open(n)) => assert!(
            matches!(
                n.tls,
                TlsMode::Required {
                    sni: "db",
                    alpn: "h2,http/1.1",
                    trust: 7
                }
            ) && n.egress == 3
        ),
        _ => panic!("OPEN REQUIRED"),
    }
    match decode_need(&need(op::OPEN, nf::TLS_MUTUAL, 0, 0, 9, 0, [DEST, E, E, E])) {
        Ok(Need::Open(n)) => assert!(matches!(n.tls, TlsMode::Mutual { cert: 9, .. })),
        _ => panic!("OPEN MUTUAL"),
    }
    for (secret, cert) in [(0, None), (4, Some(4))] {
        match decode_need(&need(
            op::OPEN,
            nf::TLS_INBAND,
            0,
            0,
            secret,
            0,
            [DEST, b"db", E, E],
        )) {
            Ok(Need::Open(n)) => {
                assert!(matches!(n.tls, TlsMode::Inband { cert: c, .. } if c == cert))
            }
            _ => panic!("OPEN INBAND"),
        }
    }
    for egress in 0..=4 {
        assert!(decode_need(&need(
            op::OPEN,
            egress << nf::EGRESS_SHIFT,
            0,
            0,
            0,
            0,
            [DEST, E, E, E]
        ))
        .is_ok());
    }
    invalid(
        &need(op::OPEN, nf::TLS_MUTUAL, 0, 0, 0, 0, [DEST, E, E, E]),
        "OPEN MUTUAL with secret 0",
    );
    invalid(
        &need(op::OPEN, 4, 0, 0, 0, 0, [DEST, E, E, E]),
        "OPEN m > 3",
    );
    invalid(
        &need(op::OPEN, 5 << nf::EGRESS_SHIFT, 0, 0, 0, 0, [DEST, E, E, E]),
        "OPEN egress 5",
    );
    invalid(
        &need(op::OPEN, 0x200, 0, 0, 0, 0, [DEST, E, E, E]),
        "OPEN with the retired 0x200",
    );
    invalid(
        &need(op::OPEN, nf::REUSABLE, 0, 0, 0, 0, [DEST, E, E, E]),
        "OPEN with REUSABLE",
    );
    invalid(&need(op::OPEN, 0, 0, 0, 0, 0, [E; 4]), "OPEN with no dest");
    // STARTTLS: TLS_MASK only, c must be 0; REQUIRED or MUTUAL with a cert.
    match decode_need(&need(
        op::STARTTLS,
        nf::TLS_REQUIRED,
        3,
        0,
        0,
        2,
        [b"db", b"postgresql", E, E],
    )) {
        Ok(Need::StartTls { conn, tls }) => {
            assert_eq!(conn.0, 3);
            assert!(matches!(
                tls,
                TlsMode::Required {
                    sni: "db",
                    alpn: "postgresql",
                    trust: 2
                }
            ));
        }
        _ => panic!("STARTTLS REQUIRED"),
    }
    assert!(matches!(
        decode_need(&need(
            op::STARTTLS,
            nf::TLS_MUTUAL,
            3,
            0,
            5,
            0,
            [b"db", E, E, E]
        )),
        Ok(Need::StartTls {
            tls: TlsMode::Mutual { cert: 5, .. },
            ..
        })
    ));
    invalid(
        &need(op::STARTTLS, nf::TLS_NONE, 3, 0, 0, 0, [E; 4]),
        "STARTTLS NONE",
    );
    invalid(
        &need(op::STARTTLS, nf::TLS_INBAND, 3, 0, 0, 0, [E; 4]),
        "STARTTLS INBAND",
    );
    invalid(
        &need(op::STARTTLS, nf::TLS_MUTUAL, 3, 0, 0, 0, [E; 4]),
        "STARTTLS MUTUAL with secret 0",
    );
    invalid(
        &need(
            op::STARTTLS,
            nf::TLS_REQUIRED | (1 << nf::EGRESS_SHIFT),
            3,
            0,
            0,
            0,
            [E; 4],
        ),
        "STARTTLS with a class",
    );
    invalid(
        &need(op::STARTTLS, nf::TLS_REQUIRED, 0, 0, 0, 0, [E; 4]),
        "STARTTLS on conn 0",
    );
    // FETCH: NONE → cert None; MUTUAL with a cert → Some; class 0..=4; headers are PAIRs.
    let headers = nested(|r| r.put_pair(tag::PAIR, "accept", b"*/*").expect("pair"));
    match decode_need(&need(
        op::FETCH,
        nf::TLS_NONE | egress,
        0,
        1 << 20,
        0,
        3,
        [b"GET", b"https://a.example/x", &headers, b"body"],
    )) {
        Ok(Need::Fetch(f)) => {
            assert!(f.method == "GET" && f.url == "https://a.example/x" && f.body == b"body");
            assert!(f.cert.is_none() && f.trust == 3 && f.max_body == 1 << 20 && f.egress == 3);
            assert_eq!(f.headers.count(), 1);
        }
        _ => panic!("FETCH NONE"),
    }
    assert!(matches!(
        decode_need(&need(op::FETCH, nf::TLS_MUTUAL, 0, 0, 8, 0, [b"POST", b"https://a/x", E, E])),
        Ok(Need::Fetch(f)) if f.cert == Some(8)
    ));
    invalid(
        &need(
            op::FETCH,
            nf::TLS_REQUIRED,
            0,
            0,
            0,
            0,
            [b"GET", b"https://a/x", E, E],
        ),
        "FETCH REQUIRED",
    );
    invalid(
        &need(
            op::FETCH,
            nf::TLS_INBAND,
            0,
            0,
            0,
            0,
            [b"GET", b"https://a/x", E, E],
        ),
        "FETCH INBAND",
    );
    invalid(
        &need(
            op::FETCH,
            nf::TLS_MUTUAL,
            0,
            0,
            0,
            0,
            [b"GET", b"https://a/x", E, E],
        ),
        "FETCH MUTUAL with secret 0",
    );
    invalid(
        &need(
            op::FETCH,
            5 << nf::EGRESS_SHIFT,
            0,
            0,
            0,
            0,
            [b"GET", b"https://a/x", E, E],
        ),
        "FETCH egress 5",
    );
    invalid(
        &need(
            op::FETCH,
            0,
            0,
            0,
            0,
            0,
            [b"GET", b"https://a/x", b"not records", E],
        ),
        "FETCH headers not PAIRs",
    );
    // The other ops: exactly the fields the wire table names.
    assert!(matches!(
        decode_need(&need(op::WRITE, 0, 4, 0, 0, 0, [b"bytes", E, E, E])),
        Ok(Need::Write {
            bytes: b"bytes",
            ..
        })
    ));
    assert!(matches!(
        decode_need(&need(op::READ, 0, 4, 512, 0, 0, [E; 4])),
        Ok(Need::Read { max: 512, .. })
    ));
    assert!(matches!(
        decode_need(&need(op::CLOSE, nf::REUSABLE, 4, 0, 0, 0, [E; 4])),
        Ok(Need::Close { reusable: true, .. })
    ));
    assert!(matches!(
        decode_need(&need(op::SECRET, 0, 0, 0, 2, 0, [E; 4])),
        Ok(Need::Secret { handle: 2 })
    ));
    invalid(&need(op::READ, 0, 4, 0, 0, 0, [E; 4]), "READ of 0 bytes");
    invalid(
        &need(op::CLOSE, nf::TLS_REQUIRED, 4, 0, 0, 0, [E; 4]),
        "CLOSE with a TLS mode",
    );
    invalid(&need(op::SECRET, 0, 0, 0, 0, 0, [E; 4]), "SECRET handle 0");
    invalid(
        &need(op::WRITE, 0, 0, 0, 0, 0, [b"x", E, E, E]),
        "WRITE on conn 0",
    );
    assert!(matches!(
        decode_need(&need(op::RECORD, nf::REC_GET, 0, 0, 0, 0, [b"k", E, E, E])),
        Ok(Need::Record(RecordNeed::Get(b"k")))
    ));
    assert!(matches!(
        decode_need(&need(
            op::RECORD,
            nf::REC_PUT,
            60,
            0,
            0,
            0,
            [b"k", b"v", E, E]
        )),
        Ok(Need::Record(RecordNeed::Put(b"k", b"v", 60)))
    ));
    assert!(matches!(
        decode_need(&need(
            op::RECORD,
            nf::REC_LIST,
            0,
            50,
            0,
            0,
            [b"p", E, E, E]
        )),
        Ok(Need::Record(RecordNeed::List(b"p", 50)))
    ));
    invalid(
        &need(op::RECORD, 9, 0, 0, 0, 0, [b"k", E, E, E]),
        "RECORD op 9",
    );
    invalid(
        &need(op::RECORD, nf::REC_COMMIT, 0, 0, 0, 0, [E; 4]),
        "an empty COMMIT",
    );
    // DIRECTORY: every op's accepted shape, and the rows that refuse.
    let id = b"subject-1";
    let indexes = nested(|r| r.put_pair(tag::PAIR, "email", b"a@b").expect("pair"));
    let members = nested(|r| {
        r.put(dir::DM_ADD, b"u1").expect("add");
        r.put(dir::DM_REMOVE, b"u2").expect("remove");
    });
    let (s, g, m) = (dir::SUBJECT, dir::GROUP, dir::MEMBER);
    let ok: [(u32, u64, [&[u8]; 4], &str); 9] = [
        (dflags(dir::GET, s, 0, 0, false), 0, [id, E, E, E], "GET"),
        (
            dflags(dir::LOOKUP, s, 0, 0, false),
            0,
            [b"email", b"a@b", E, E],
            "LOOKUP",
        ),
        (
            dflags(dir::SCAN, s, 0, 0, false),
            0,
            [E, E, E, E],
            "SCAN subjects",
        ),
        (
            dflags(dir::SCAN, m, 0, 0, false),
            10,
            [b"group-1", b"u1", E, E],
            "SCAN members",
        ),
        (
            dflags(dir::COUNT, g, 0, 0, false),
            0,
            [E; 4],
            "COUNT groups",
        ),
        (
            dflags(dir::CREATE, s, 0, dir::STATE_ACTIVE, true),
            0,
            [E, b"{}", &indexes, E],
            "CREATE subject",
        ),
        (
            dflags(dir::CREATE, g, 0, 0, false),
            0,
            [E, b"{}", E, E],
            "CREATE group",
        ),
        (
            dflags(
                dir::APPLY,
                g,
                dir::APPLY_DOCUMENT | dir::APPLY_REPLACE_MEMBERS,
                0,
                false,
            ),
            3,
            [b"group-1", b"{}", E, &members],
            "APPLY group",
        ),
        (
            dflags(dir::DELETE, s, 0, 0, false),
            2,
            [id, E, E, E],
            "DELETE",
        ),
    ];
    for (flags, a, args, why) in ok {
        assert!(
            matches!(
                decode_need(&need(op::DIRECTORY, flags, a, 0, 0, 0, args)),
                Ok(Need::Directory(_))
            ),
            "{why}"
        );
    }
    match decode_need(&need(
        op::DIRECTORY,
        dflags(dir::SCAN, s, 0, 0, false),
        0,
        0,
        0,
        0,
        [E; 4],
    )) {
        Ok(Need::Directory(DirNeed::Scan { limit, .. })) => {
            assert_eq!(limit, dir::MAX_SCAN, "0 = MAX_SCAN")
        }
        _ => panic!("SCAN"),
    }
    let long_id = vec![b'x'; dir::MAX_ID as usize + 1];
    let refused: [(u32, u64, [&[u8]; 4], &str); 10] = [
        (dflags(8, s, 0, 0, false), 0, [id, E, E, E], "op 8"),
        (
            dflags(dir::GET, m, 0, 0, false),
            0,
            [id, E, E, E],
            "MEMBER outside SCAN/COUNT",
        ),
        (
            dflags(dir::SCAN, m, 0, 0, false),
            0,
            [E; 4],
            "MEMBER with no group",
        ),
        (
            dflags(dir::GET, s, dir::APPLY_DOCUMENT, 0, false),
            0,
            [id, E, E, E],
            "apply outside APPLY",
        ),
        (
            dflags(dir::APPLY, s, dir::APPLY_REPLACE_MEMBERS, 0, false),
            0,
            [id, E, E, E],
            "REPLACE_MEMBERS on a SUBJECT",
        ),
        (
            dflags(dir::GET, s, 0, 0, true),
            0,
            [id, E, E, E],
            "PULL outside CREATE/APPLY",
        ),
        (
            dflags(dir::CREATE, s, 0, 0, false),
            0,
            [E, b"{}", E, E],
            "CREATE subject without a state",
        ),
        (
            dflags(dir::CREATE, g, 0, dir::STATE_ACTIVE, false),
            0,
            [E, b"{}", E, E],
            "a state on a GROUP",
        ),
        (
            dflags(dir::GET, s, 0, 0, false),
            0,
            [&long_id, E, E, E],
            "an id over MAX_ID",
        ),
        (
            dflags(dir::GET, s, 0, 0, false),
            0,
            [id, b"unused", E, E],
            "an unused argument",
        ),
    ];
    for (flags, a, args, why) in refused {
        invalid(&need(op::DIRECTORY, flags, a, 0, 0, 0, args), why);
    }
    invalid(
        &need(
            op::DIRECTORY,
            dflags(dir::GET, s, 0, 0, false),
            0,
            0,
            1,
            0,
            [id, E, E, E],
        ),
        "DIRECTORY with a secret",
    );
}

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): HostNeeds never learns which destinations the operator configured (busbar-core-connector need.rs: `configured` is always None, no setter), so `judged_class(OPEN_WEB, configured)` is never lifted and a counting-guard arm would be red; the arm then moves into busbar-core-connector beside HostNeeds (not a dependency of this crate). The unix half runs as busbar_core_connector::need::unix::tests::only_operator_infrastructure_may_dial_a_unix_socket"]
fn hostneeds_judges_the_stated_class() {
    todo!("owner: W1-C1A (C-NEED-DECODE)")
}
