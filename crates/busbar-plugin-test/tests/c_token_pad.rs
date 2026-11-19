// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TOKEN-PAD (ABI-MIN3-INTERFACE §14 round 6): a session opener's answer begins with exactly one 16-byte TOKEN
//! record and the next record starts at offset 16. The codec arm is W1-A1's (merged; its crate test is
//! `busbar-plugin-abi` tests/records.rs); the opener arm (W1-H1) runs through the typed session proxies over
//! C-OPENER-REFUSE's fixtures.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::records::{tag, Records, Reply, TokenRec, Writer};

#[test]
fn a_token_record_is_16_bytes_and_the_next_record_starts_at_16() {
    let mut reply = Reply::new();
    reply
        .put_pod(
            tag::TOKEN,
            &TokenRec {
                token: (1 << 32) | 1,
            },
        )
        .expect("token");
    reply.put_text(tag::TEXT, "after").expect("text");
    let bytes = reply.as_bytes();
    assert_eq!(bytes[16..18], tag::TEXT.to_ne_bytes());
    let tags: Vec<u16> = Records::new(bytes)
        .map(|rec| rec.expect("framing").tag)
        .collect();
    assert_eq!(tags, [tag::TOKEN, tag::TEXT]);
}

/// W1-H1: every session opener's OK answer, through the typed proxies (`plane::Proxy::request`/`probe`,
/// `transport::Proxy::begin`) over C-OPENER-REFUSE's `plugin!` fixtures: the host's buffer starts with exactly one
/// 16-byte TOKEN record (RecHead 8 + TokenRec 8, bit 63 set), the plugin's own record starts at offset 16, and the
/// host's answer parse takes it with no UnknownTag(0) (a 24-byte reservation would leave a zero RecHead there). An
/// opener that writes nothing of its own answers the TOKEN alone, 16 bytes.
#[test]
fn plane_request_probe_and_transport_begin_answers_parse_with_no_unknown_tag_zero() {
    use crate::c_opener_refuse::fixture::{
        conn, counts, hosted, plane_req, target, ACCEPT, ACCEPT_BARE, MAX_OUT,
    };
    use busbar_plugin_abi::fail::CallError;
    use busbar_plugin_abi::host_side::answer::Answer;
    use busbar_plugin_abi::host_side::pool::{Pool, PooledOut};
    use busbar_plugin_abi::{plane, transport};

    /// The answer's records as (tag, body), TOKEN excluded.
    fn records(answer: &Answer<'_>) -> Vec<(u16, Vec<u8>)> {
        answer
            .records()
            .map(|rec| match rec {
                Ok(rec) => (rec.tag, rec.body.to_vec()),
                Err(e) => panic!("the answer is not framed: {e:?}"),
            })
            .collect()
    }

    /// The host buffer of an OK opener answer: one TOKEN at offset 0, then `next` (a tag) at offset 16 or the end.
    fn padded(buf: &PooledOut, next: Option<u16>) {
        let bytes = buf.bytes();
        assert_eq!(bytes[0..2], tag::TOKEN.to_ne_bytes(), "TOKEN first");
        assert_eq!(bytes[4..8], 8u32.to_ne_bytes(), "a TokenRec body");
        let token = match Records::new(bytes).next() {
            Some(Ok(rec)) => rec.pod::<TokenRec>().expect("a TokenRec body").token,
            _ => panic!("a framed first record"),
        };
        assert_ne!(token & (1 << 63), 0, "a session token");
        let tags: Vec<u16> = Records::new(bytes)
            .map(|rec| rec.expect("framing").tag)
            .collect();
        match next {
            Some(next) => {
                assert_eq!(
                    bytes[16..18],
                    next.to_ne_bytes(),
                    "the plugin's record at 16"
                );
                assert_eq!(tags, [tag::TOKEN, next], "exactly one TOKEN");
            }
            None => {
                assert_eq!(bytes.len(), 16, "the TOKEN alone");
                assert_eq!(tags, [tag::TOKEN]);
            }
        }
    }

    fn opened<S>(opened: Result<(Option<S>, Answer<'_>), CallError>, want: &[(u16, Vec<u8>)]) -> S {
        let (session, answer) = match opened {
            Ok(opened) => opened,
            Err(e) => panic!("the answer parses (no UnknownTag(0)): {e:?}"),
        };
        assert!(answer.is_ok());
        assert_eq!(
            records(&answer),
            want,
            "the plugin's records, TOKEN excluded"
        );
        session.expect("an OK answer with a leading TOKEN has its session")
    }

    let planes = plane::Proxy::bind(hosted::<plane::Marker>(
        &crate::c_opener_refuse::fixture::plane_fx::PLUGIN,
        plane::ALL,
    ))
    .expect("a plane instance");
    let mut buf = Pool::global().acquire(MAX_OUT);
    let s = opened(
        planes.request(&mut buf, &plane_req(ACCEPT), b"{}"),
        &[(plane::tag::END, Vec::new())],
    );
    padded(&buf, Some(plane::tag::END));
    drop(s);
    let mut buf = Pool::global().acquire(MAX_OUT);
    let s = opened(
        planes.probe(&mut buf, &target(ACCEPT)),
        &[(plane::tag::BODY, b"GET /v1/models".to_vec())],
    );
    padded(&buf, Some(plane::tag::BODY));
    drop(s);
    let mut buf = Pool::global().acquire(MAX_OUT);
    let s = opened(planes.request(&mut buf, &plane_req(ACCEPT_BARE), b""), &[]);
    padded(&buf, None);
    drop(s);
    let mut buf = Pool::global().acquire(MAX_OUT);
    let s = opened(planes.probe(&mut buf, &target(ACCEPT_BARE)), &[]);
    padded(&buf, None);
    drop(s);

    let conns = transport::Proxy::bind(hosted::<transport::Marker>(
        &crate::c_opener_refuse::fixture::transport_fx::PLUGIN,
        transport::ALL,
    ))
    .expect("a transport instance");
    let mut buf = Pool::global().acquire(MAX_OUT);
    let s = opened(
        conns.begin(&mut buf, &conn(ACCEPT)),
        &[(transport::tag::RENDEZVOUS, b"hello".to_vec())],
    );
    padded(&buf, Some(transport::tag::RENDEZVOUS));
    drop(s);
    let mut buf = Pool::global().acquire(MAX_OUT);
    let s = opened(conns.begin(&mut buf, &conn(ACCEPT_BARE)), &[]);
    padded(&buf, None);
    drop(s);
    assert_eq!(
        counts(),
        (6, 6),
        "every session opened, and every one cancelled"
    );
}
