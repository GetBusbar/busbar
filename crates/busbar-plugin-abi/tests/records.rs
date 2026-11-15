// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-A1's arms of the records codec cases (ABI-MIN3-INTERFACE §3, §4.1, §14): C-TOKEN-PAD, C-TOKEN-SPACE,
//! C-UNKNOWN-TAG and the C-ERROR-RECORDS record order, plus the reader and writer shapes every other case uses.
//! These run before W1-T1's harness exists, over the crate's own `Reply` writer and `Records` reader.

use busbar_plugin_abi as abi;

use abi::fail::{FAIL_TEXT_WIRE_MAX, Fail, fact, failed, refused};
use abi::need::need::NeedErr;
use abi::records::{
    FactRec, FactTextRec, FailRec, Full, MetricObs, PairRec, RecErr, Records, Reply, TokenRec,
    U32Rec, Writer, metric, tag,
};
use abi::types::{Status, TOKEN_SESSION, Token};

/// A record written by hand: head, body, zero padding to the next multiple of 8.
fn record(tag: u16, reserved: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&tag.to_ne_bytes());
    bytes.extend_from_slice(&reserved.to_ne_bytes());
    let len = u32::try_from(body.len()).expect("test body fits a record");
    bytes.extend_from_slice(&len.to_ne_bytes());
    bytes.extend_from_slice(body);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    bytes
}

fn tags(bytes: &[u8]) -> Vec<u16> {
    Records::new(bytes)
        .map(|rec| rec.expect("well-formed records").tag)
        .collect()
}

/// C-TOKEN-PAD (A1 arm): a TOKEN record is exactly 16 bytes (head 8 + TokenRec 8), so the record after it
/// starts at offset 16 and nothing reads a zero head (UnknownTag(0)) between them.
#[test]
fn a_token_record_is_sixteen_bytes_and_the_next_record_starts_at_sixteen() {
    let mut reply = Reply::new();
    reply
        .put_pod(
            tag::TOKEN,
            &TokenRec {
                token: (1 << 32) | 7,
            },
        )
        .expect("token fits");
    assert_eq!(reply.len(), 16);
    reply.put_text(tag::TEXT, "next").expect("text fits");
    let bytes = reply.as_bytes();
    assert_eq!(bytes.len(), 32);
    assert_eq!(bytes[16..18], tag::TEXT.to_ne_bytes());
    let recs: Vec<_> = Records::new(bytes)
        .collect::<Result<_, _>>()
        .expect("records");
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].tag, tag::TOKEN);
    assert_eq!(
        recs[0].pod::<TokenRec>().expect("token pod").token,
        (1 << 32) | 7
    );
    assert_eq!(recs[1].tag, tag::TEXT);
    assert_eq!(recs[1].text().expect("utf-8"), "next");
    assert!(recs.iter().all(|rec| rec.tag != 0));
}

/// C-TOKEN-SPACE (A1 arm): a chain token and a session token for the same slot differ in bit 63 only, and a
/// TOKEN record carries either one unchanged, so the shim can tell the spaces apart (§2, §6.5).
#[test]
fn chain_and_session_tokens_differ_in_bit_63_and_cross_the_wire_unchanged() {
    let chain: Token = (3 << 32) | 41;
    let session: Token = chain | TOKEN_SESSION;
    assert_eq!(TOKEN_SESSION, 1 << 63);
    assert_eq!(chain & TOKEN_SESSION, 0);
    assert_eq!(session & TOKEN_SESSION, TOKEN_SESSION);
    assert_eq!(session & !TOKEN_SESSION, chain);
    let mut reply = Reply::new();
    reply
        .put_pod(tag::TOKEN, &TokenRec { token: chain })
        .expect("token");
    reply
        .put_pod(tag::TOKEN, &TokenRec { token: session })
        .expect("token");
    let read: Vec<Token> = Records::new(reply.as_bytes())
        .map(|rec| {
            rec.and_then(|rec| rec.pod::<TokenRec>())
                .expect("token")
                .token
        })
        .collect();
    assert_eq!(read, [chain, session]);
}

/// C-UNKNOWN-TAG (A1 arm): the reader judges framing only and hands every tag through as written, so the
/// positional decoder can answer FAULT UnknownTag: the retired 0x000A (MIGRATED), a zero tag and an undeclared
/// kind tag all arrive unchanged. The generic table never reuses 0x000A or 0 and has no duplicate.
#[test]
fn the_reader_hands_every_tag_through_for_the_decoder_to_judge() {
    let mut bytes = record(0x000A, 0, b"");
    bytes.extend(record(0, 0, b"x"));
    bytes.extend(record(0x01FF, 0, &[1, 2, 3]));
    let recs: Vec<_> = Records::new(&bytes)
        .collect::<Result<_, _>>()
        .expect("framing is sound");
    assert_eq!(
        recs.iter().map(|rec| rec.tag).collect::<Vec<_>>(),
        [0x000A, 0, 0x01FF]
    );
    assert_eq!(recs[0].body, b"");
    assert_eq!(recs[1].body, b"x");
    assert_eq!(recs[2].body, [1, 2, 3]);

    let mut generic = vec![
        tag::TEXT,
        tag::FAIL,
        tag::TOKEN,
        tag::NEED,
        tag::NEED_RES,
        tag::FACT,
        tag::FACT_TEXT,
        tag::PAIR,
        tag::INSTANCE,
        tag::CONFIG,
        tag::CORE_CFG,
        tag::ERROR,
        tag::H_METHOD,
        tag::H_PATH,
        tag::H_AUTHORITY,
        tag::H_SCHEME,
        tag::H_STATUS,
        tag::H_BUDGET_NS,
        tag::H_BODY_LEN,
        tag::CONVERSATION,
        tag::ID_SUBJECT,
        tag::ID_GROUP,
        tag::ID_CLAIM,
        tag::D_METHODS,
        tag::D_FACTS,
        tag::D_SCHEMA,
        tag::D_MAX_OUT,
        tag::D_CEILING,
        tag::D_SECRET_PATH,
        tag::D_TRUST_PATH,
        tag::D_DEST_PATH,
        tag::D_REF_PATH,
        tag::D_PUBLIC_URL_PATH,
        tag::D_CALLER_UPSTREAMS_PATH,
        tag::D_ERRORS,
        tag::D_METRIC,
        tag::METRIC,
        tag::REC_PRED,
        tag::REC_PUT,
        tag::REC_DEL,
        tag::ENDPOINT,
    ];
    let count = generic.len();
    assert!(generic.iter().all(|&t| t != 0 && t != 0x000A && t < 0x0100));
    // 0x0070..=0x0074 are DIRECTORY's nested tags (need.rs `dir`), reserved in the generic range.
    assert!(generic.iter().all(|&t| !(0x0070..=0x0074).contains(&t)));
    generic.sort();
    generic.dedup();
    assert_eq!(generic.len(), count, "a generic tag number is used twice");
}

/// The reader's framing errors: a non-zero `_r`, a head or body past the end, missing or non-zero padding.
/// The first error ends the iteration (fused).
#[test]
fn a_bad_head_ends_the_records_with_one_error() {
    let mut reserved = record(tag::TEXT, 1, b"a");
    reserved.extend(record(tag::TEXT, 0, b"b"));
    let mut it = Records::new(&reserved);
    assert!(matches!(it.next(), Some(Err(RecErr::Reserved))));
    assert!(it.next().is_none());
    assert!(it.next().is_none());

    let whole = record(tag::TEXT, 0, b"abc");
    assert_eq!(whole.len(), 16);
    // A head cut short, a body cut short, and a body whose padding is missing.
    for cut in [3, 10, 11] {
        let mut it = Records::new(&whole[..cut]);
        assert!(
            matches!(it.next(), Some(Err(RecErr::Truncated))),
            "cut at {cut}"
        );
        assert!(it.next().is_none());
    }
    let mut dirty = whole.clone();
    dirty[12] = 0xFF;
    assert!(matches!(
        Records::new(&dirty).next(),
        Some(Err(RecErr::Reserved))
    ));
    let mut long = whole.clone();
    long[4..8].copy_from_slice(&100u32.to_ne_bytes());
    assert!(matches!(
        Records::new(&long).next(),
        Some(Err(RecErr::Truncated))
    ));
    assert!(Records::new(&[]).next().is_none());
}

/// Pods, tails, text and pairs read back exactly; a wrong size is Size, bad UTF-8 is Utf8.
#[test]
fn pods_tails_text_and_pairs_read_back_exactly() {
    let mut reply = Reply::new();
    reply
        .put_pair(tag::PAIR, "content-type", b"application/json")
        .expect("pair");
    reply
        .put_fact_text(fact::PJ_MODEL, "model-a")
        .expect("fact text");
    reply.put_fact(fact::PJ_STREAM, 1).expect("fact");
    reply.put(tag::TEXT, &[0xFF, 0xFE]).expect("raw");
    reply
        .put_pod_tail(tag::PAIR, &PairRec { name_len: 9, _r: 0 }, b"ab")
        .expect("short pair");
    let recs: Vec<_> = Records::new(reply.as_bytes())
        .collect::<Result<_, _>>()
        .expect("records");
    assert_eq!(recs.len(), 5);

    let (name, value) = recs[0].pair().expect("pair");
    assert_eq!((name, value), ("content-type", &b"application/json"[..]));

    assert_eq!(recs[1].tag, tag::FACT_TEXT);
    let (head, text) = recs[1].pod_tail::<FactTextRec>().expect("fact text");
    assert_eq!(
        (head.key, head._r, text),
        (fact::PJ_MODEL, 0, &b"model-a"[..])
    );
    assert!(matches!(recs[1].pod::<FactRec>(), Err(RecErr::Size)));

    assert_eq!(recs[2].tag, tag::FACT);
    let fact_rec = recs[2].pod::<FactRec>().expect("fact");
    assert_eq!((fact_rec.key, fact_rec.value), (fact::PJ_STREAM, 1));

    assert!(matches!(recs[3].text(), Err(RecErr::Utf8)));
    assert!(matches!(recs[4].pair(), Err(RecErr::Size)));
}

/// `put_nested` back-patches the head's length over its nested records (nesting inside nesting too), and
/// `put_metric` writes MetricObs then one nested PAIR per label value, in the declared key order.
#[test]
fn nested_records_and_metrics_are_back_patched() {
    let mut reply = Reply::new();
    reply
        .put_nested(0x0101, |n| {
            n.put_text(tag::TEXT, "a")?;
            n.put_pair(tag::PAIR, "k", b"v")?;
            n.put_nested(0x0102, |inner| inner.put_fact(fact::PJ_TOOL_COUNT, 2))
        })
        .expect("nested");
    reply
        .put_metric(7, metric::MX_ADD, 1.5, &["a", "bb"])
        .expect("metric");
    let recs: Vec<_> = Records::new(reply.as_bytes())
        .collect::<Result<_, _>>()
        .expect("records");
    assert_eq!(recs.len(), 2);

    assert_eq!(recs[0].tag, 0x0101);
    // TEXT "a" (16) + PAIR "k"/"v" (24) + nested FACT (8 + 24 = 32).
    assert_eq!(recs[0].body.len(), 72);
    let inner: Vec<_> = recs[0]
        .nested()
        .collect::<Result<_, _>>()
        .expect("nested records");
    assert_eq!(
        inner.iter().map(|rec| rec.tag).collect::<Vec<_>>(),
        [tag::TEXT, tag::PAIR, 0x0102]
    );
    assert_eq!(inner[0].text().expect("text"), "a");
    assert_eq!(inner[1].pair().expect("pair"), ("k", &b"v"[..]));
    assert_eq!(tags(inner[2].body), [tag::FACT]);

    assert_eq!(recs[1].tag, tag::METRIC);
    let (obs, labels) = recs[1].pod_tail::<MetricObs>().expect("metric");
    assert_eq!((obs.id, obs.op, obs.value), (7, metric::MX_ADD, 1.5));
    let labels: Vec<_> = Records::new(labels)
        .map(|rec| rec.and_then(|rec| rec.pair()).expect("label pair"))
        .collect();
    assert_eq!(labels, [("", &b"a"[..]), ("", &b"bb"[..])]);
}

/// A reply grows through many blocks and keeps every byte in order (each growth moves the bytes into a fresh
/// block, §3.2).
#[test]
fn a_reply_keeps_every_record_across_growth() {
    for mut reply in [Reply::new(), Reply::with_capacity(4096), Reply::default()] {
        let body = [0x5A_u8; 100];
        for i in 0..300u16 {
            reply.put(0x0100 | (i & 0x7F), &body).expect("fits");
        }
        // 300 records of 8 + 100 bytes, each padded to 112.
        assert_eq!(reply.len(), 300 * 112);
        let recs: Vec<_> = Records::new(reply.as_bytes())
            .collect::<Result<_, _>>()
            .expect("records");
        assert_eq!(recs.len(), 300);
        assert!(
            recs.iter()
                .enumerate()
                .all(|(i, rec)| { rec.tag == 0x0100 | (i as u16 & 0x7F) && rec.body == body })
        );
    }
}

/// C-ERROR-RECORDS, record-order arm (round 34): a numbered FAILED Fail is written as FAIL, then one ERROR
/// (only because the number is not 0), then its facts, and the longest such answer (FAIL with 3,072 bytes of
/// detail + ERROR + two FACTs) fits the first 4 KiB buffer without `grow`.
#[test]
fn a_numbered_failure_writes_fail_then_error_then_facts_inside_the_first_buffer() {
    let detail = "x".repeat(FAIL_TEXT_WIRE_MAX);
    let fail = Fail::failed_because(failed::F_UPSTREAM, detail)
        .with_fact(fact::FACT_BACKEND_STATUS, 503)
        .with_fact(fact::FACT_RETRY_AFTER_S, 30)
        .with_error(7071);
    assert_eq!(fail.status(), Status::FAILED);
    assert_eq!(fail.code(), failed::F_UPSTREAM);
    assert_eq!(fail.error(), 7071);
    assert_eq!(fail.text().len(), FAIL_TEXT_WIRE_MAX);
    // Facts come out in FAIL_FACT_KEYS order, whatever order they were set in.
    assert_eq!(fail.facts().collect::<Vec<_>>(), [(1, 30), (2, 503)]);

    // The records in the order the shim writes them (§6.4 step 2).
    let mut reply = Reply::new();
    reply
        .put_pod_tail(
            tag::FAIL,
            &FailRec {
                status: fail.status().0,
                code: fail.code(),
            },
            fail.text().as_bytes(),
        )
        .expect("fail");
    if fail.error() != 0 {
        reply
            .put_pod(
                tag::ERROR,
                &U32Rec {
                    value: u32::from(fail.error()),
                    _r: 0,
                },
            )
            .expect("error");
    }
    for (key, value) in fail.facts() {
        reply.put_fact(key, value).expect("fact");
    }
    // FAIL 8 + 8 + 3,072; ERROR 8 + 8; two FACTs 2 x (8 + 16).
    assert_eq!(reply.len(), 3_088 + 16 + 48);
    assert!(reply.len() <= 4096);

    let recs: Vec<_> = Records::new(reply.as_bytes())
        .collect::<Result<_, _>>()
        .expect("records");
    assert_eq!(
        recs.iter().map(|rec| rec.tag).collect::<Vec<_>>(),
        [tag::FAIL, tag::ERROR, tag::FACT, tag::FACT]
    );
    let (head, text) = recs[0].pod_tail::<FailRec>().expect("fail pod");
    assert_eq!((head.status, head.code), (2, failed::F_UPSTREAM));
    assert_eq!(text.len(), FAIL_TEXT_WIRE_MAX);
    let error = recs[1].pod::<U32Rec>().expect("error pod");
    assert_eq!((error.value, error._r), (7071, 0));
    let facts: Vec<_> = recs[2..]
        .iter()
        .map(|rec| {
            let f = rec.pod::<FactRec>().expect("fact pod");
            (f.key, f.value)
        })
        .collect();
    assert_eq!(facts, [(1, 30), (2, 503)]);

    // Number 0 writes no ERROR record.
    let plain = Fail::failed(failed::F_UPSTREAM).with_error(9).with_error(0);
    assert_eq!(plain.error(), 0);
}

/// `Fail`: REFUSED carries no facts but may carry an error number (display only); a key outside
/// FAIL_FACT_KEYS is ignored; setting a fact again replaces it.
#[test]
fn a_fail_carries_facts_only_when_failed_and_a_number_either_way() {
    let verdict = Fail::refused_because(refused::R_DENIED, "denied by the backend")
        .with_fact(fact::FACT_RETRY_AFTER_S, 9)
        .with_error(12);
    assert_eq!(verdict.status(), Status::REFUSED);
    assert_eq!(verdict.code(), refused::R_DENIED);
    assert_eq!(verdict.text(), "denied by the backend");
    assert_eq!(verdict.facts().count(), 0);
    assert_eq!(verdict.error(), 12);

    let bare = Fail::refused(refused::R_NOT_FOUND);
    assert_eq!(
        (bare.status(), bare.code(), bare.text(), bare.error()),
        (Status::REFUSED, refused::R_NOT_FOUND, "", 0)
    );
    let unsupported = Fail::unsupported();
    assert_eq!(
        (unsupported.status(), unsupported.code()),
        (Status::REFUSED, refused::R_UNSUPPORTED)
    );

    let busy = Fail::failed_because(failed::F_BUSY, String::from("locked"))
        .with_fact(fact::PJ_MODEL, 1)
        .with_fact(fact::FACT_BACKEND_STATUS, 502)
        .with_fact(fact::FACT_BACKEND_STATUS, 503);
    assert_eq!(busy.status(), Status::FAILED);
    assert_eq!(busy.text(), "locked");
    assert_eq!(busy.facts().collect::<Vec<_>>(), [(2, 503)]);
    assert_eq!(Fail::failed(failed::F_INTERNAL).facts().count(), 0);
}

/// The fixed conversions: a Need error (§6.3 mapping), a full writer and a record error.
#[test]
fn step_and_codec_errors_map_to_their_fixed_verdicts() {
    let cases = [
        (NeedErr::Denied, Status::REFUSED, refused::R_DENIED),
        (NeedErr::Absent, Status::REFUSED, refused::R_NOT_FOUND),
        (NeedErr::Taken, Status::REFUSED, refused::R_CONFLICT),
        (NeedErr::Unavailable, Status::FAILED, failed::F_UNAVAILABLE),
        (NeedErr::Closed, Status::FAILED, failed::F_UNAVAILABLE),
        (NeedErr::Tls, Status::FAILED, failed::F_UNAVAILABLE),
        (NeedErr::Timeout, Status::FAILED, failed::F_TIMEOUT),
        (NeedErr::Limit, Status::FAILED, failed::F_LIMIT),
        (NeedErr::Skipped, Status::FAILED, failed::F_INTERNAL),
        (NeedErr::Invalid, Status::FAILED, failed::F_INTERNAL),
    ];
    for (err, status, code) in cases {
        let fail = Fail::from(err);
        assert_eq!((fail.status(), fail.code()), (status, code), "{err:?}");
        assert!(!fail.text().is_empty(), "{err:?} carries its fixed text");
    }
    let full = Fail::from(Full);
    assert_eq!(
        (full.status(), full.code()),
        (Status::FAILED, failed::F_LIMIT)
    );
    let bad = Fail::from(RecErr::Size);
    assert_eq!(
        (bad.status(), bad.code()),
        (Status::REFUSED, refused::R_INVALID)
    );
}

/// The generic refusal codes and projection fact keys keep their frozen numbers (IF §4.1), and `next_rec` is the
/// iterator's own step.
#[test]
fn the_generic_codes_and_projection_keys_are_frozen() {
    assert_eq!(
        [
            refused::R_AUTH_REQUIRED,
            refused::R_BAD_CREDENTIAL,
            refused::R_EXPIRED,
            refused::R_RATE_LIMITED,
            refused::R_BUDGET,
            refused::R_NO_ROUTE,
            refused::R_POLICY,
        ],
        [7, 8, 9, 10, 11, 12, 13]
    );
    assert_eq!(
        [
            fact::PJ_MODEL,
            fact::PJ_TOTAL_CHARS,
            fact::PJ_MESSAGE_COUNT,
            fact::PJ_TOOL_COUNT,
            fact::PJ_SYSTEM_CHARS,
            fact::PJ_STREAM,
            fact::PJ_MAX_TOKENS,
            fact::PJ_END_USER,
            fact::PJ_TEXT_COMPLETE,
        ],
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
    );
    let bytes = record(tag::TEXT, 0, b"one");
    let mut recs = Records::new(&bytes);
    assert_eq!(
        recs.next_rec()
            .expect("one record")
            .expect("well-formed")
            .text()
            .expect("utf-8"),
        "one"
    );
    assert!(recs.next_rec().is_none());
}
