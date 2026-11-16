// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-side answers and the one METRIC decoder (IF §10.2, §12.17). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H1 fills it.

use core::marker::PhantomData;

use crate::host_side::pool::PooledOut;
use crate::records::Records;
use crate::types::Status;

pub struct Answer<'o> {
    pub status: Status,
    recs: Records<'o>,
}
impl<'o> Answer<'o> {
    /// OK: the answer records, excluding a leading TOKEN record. REFUSED/FAILED: empty (the answer is exactly
    /// one FAIL record, §6.4 step 2; round 21: on FAILED, followed by ≤ 2 FACT records with distinct keys in
    /// `FAIL_FACT_KEYS`, validated when the answer is built; any other record next to FAIL is FAULT BadRecords).
    /// Round 34: the validated tail is FAIL, at most one ERROR directly after it (REFUSED or FAILED), then the
    /// FAILED-only FACTs; a second ERROR or one after a FACT is FAULT BadRecords, and ERROR in an OK or NEED
    /// answer is FAULT UnknownTag (§3).
    pub fn records(&self) -> Records<'o> {
        let _ = &self.recs;
        todo!()
    }
    /// Round 21: a fact a FAILED answer carried after FAIL (`FACT_RETRY_AFTER_S`, `FACT_BACKEND_STATUS`); None
    /// for OK, REFUSED, or when absent. Read by the one `PortError::Failed` builder every adapter uses.
    pub fn fail_fact(&self, key: u32) -> Option<u64> {
        let _ = key;
        todo!()
    }
    /// Round 34: the ERROR number a REFUSED or FAILED answer carried after FAIL, as the raw `u32` it arrived as
    /// (0 = none, also for OK). Never narrowed here: the shared `PortError`/`OpenError` builder resolves it
    /// through the image's `ErrorBook` (§11.2), which treats anything above 9999 as not declared.
    pub fn fail_error(&self) -> u32 {
        todo!()
    }
    /// (code, text) for REFUSED or FAILED. The text is re-validated as UTF-8 and is **not cut** by the host
    /// (round 15: it is ≤ `FAIL_TEXT_WIRE_MAX`, the shim's wire bound). It is the plugin's raw text: adapters pass
    /// it through `scrub::fail_text` (§12.16: scrub, mask a trailing partial needle, then cut to 512) before it
    /// becomes a `PortError` text, a log line or an audit field; no core path cuts it before that call.
    pub fn fail(&self) -> Option<(u32, &'o str)> {
        todo!()
    }
    // W0-ABI: `pub(crate) fn session_token(&self) -> Option<Token>` (IF §10.2: the session token a session
    // opener answered with, bit 63 checked; read only by the §10.4 session-handle constructor) lands with
    // W1-H1 together with its caller (a crate-private fn with no caller would warn as dead code).
    pub fn is_ok(&self) -> bool {
        todo!()
    }
}

/// An async answer: owns its pooled buffer.
pub struct OwnedAnswer {
    status: Status,
    buf: PooledOut,
}
impl OwnedAnswer {
    pub fn answer(&self) -> Answer<'_> {
        let _ = (&self.status, &self.buf);
        todo!()
    }
}

// W0-ABI gap: the IF (§12.17, §8.8) names `abi::host::decode_metrics(answer, &mut impl FnMut(MetricObsIn<'_>))`
// but defines neither `MetricObsIn` nor the exact parameter/return types. `MetricObsIn` is an opaque stub here
// and `decode_metrics` takes `&Answer<'_>` and returns nothing; W1-H1 (with K8) freezes both.
// One decoded METRIC observation of an answer (§3 `MetricObs` plus its PAIR* label values).
pub struct MetricObsIn<'a> {
    _stub: PhantomData<&'a ()>,
}

// The one decoder of the generic METRIC records of every kind's answer, into core's recorder (§12.17, §8.8);
// no adapter decodes them itself.
pub fn decode_metrics(answer: &Answer<'_>, f: &mut impl FnMut(MetricObsIn<'_>)) {
    let _ = (answer, f);
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fail::fact::{FACT_BACKEND_STATUS, FACT_RETRY_AFTER_S};
    use crate::host_side::pool::Pool;
    use crate::records::{Reply, TokenRec, Writer};
    use zerocopy::IntoBytes;

    fn fail(status: Status, code: u32, text: &str) -> Reply {
        let mut r = Reply::new();
        r.put_pod_tail(
            tag::FAIL,
            &FailRec {
                status: status.0,
                code,
            },
            text.as_bytes(),
        )
        .expect("fail");
        r
    }
    fn error(r: &mut Reply, value: u32) {
        r.put_pod(tag::ERROR, &U32Rec { value, _r: 0 })
            .expect("error");
    }
    fn fact(r: &mut Reply, key: u32, value: u64) {
        r.put_fact(key, value).expect("fact");
    }

    #[test]
    fn an_ok_answer_hides_a_leading_token_and_hands_kind_records_through() {
        let mut r = Reply::new();
        r.put_pod(
            tag::TOKEN,
            &TokenRec {
                token: (1 << 63) | 5,
            },
        )
        .expect("token");
        r.put(tag::TEXT, b"hello").expect("text");
        r.put(0x0150, b"kind record").expect("kind");
        let a = Answer::parse(Status::OK, r.as_bytes()).expect("valid");
        assert!(a.is_ok());
        let tags: Vec<u16> = a.records().map(|rec| rec.expect("framed").tag).collect();
        assert_eq!(tags, [tag::TEXT, 0x0150]);
        assert_eq!(
            (a.fail(), a.fail_error(), a.fail_fact(FACT_RETRY_AFTER_S)),
            (None, 0, None)
        );
    }

    #[test]
    fn an_ok_answer_with_a_record_out_of_place_faults_unknown_tag() {
        for bad in [
            tag::FAIL,
            tag::NEED,
            tag::NEED_RES,
            tag::ERROR,
            0x000A,
            0x0000,
            0x0070,
            0x0099,
            0x0200,
            0xFFFF,
        ] {
            let mut r = Reply::new();
            r.put(tag::TEXT, b"x").expect("text");
            r.put(bad, &[0u8; 16]).expect("bad");
            assert_eq!(
                Answer::parse(Status::OK, r.as_bytes()).err(),
                Some(FaultReason::UnknownTag(bad)),
                "tag {bad:#06x}"
            );
        }
        let mut r = Reply::new();
        r.put(tag::TEXT, b"x").expect("text");
        r.put_pod(tag::TOKEN, &TokenRec { token: 7 })
            .expect("token");
        assert_eq!(
            Answer::parse(Status::OK, r.as_bytes()).err(),
            Some(FaultReason::UnknownTag(tag::TOKEN)),
            "a TOKEN that is not first"
        );
        assert!(matches!(
            Answer::parse(Status::OK, &[1, 0, 0, 0, 9, 0, 0, 0]).err(),
            Some(FaultReason::BadRecords(_))
        ));
    }

    #[test]
    fn the_fail_tail_accepted_forms() {
        let r = fail(Status::REFUSED, 4, "denied");
        let a = Answer::parse(Status::REFUSED, r.as_bytes()).expect("plain refusal");
        assert_eq!(a.fail(), Some((4, "denied")));
        assert_eq!(a.records().count(), 0, "REFUSED has no records");
        let mut r = fail(Status::REFUSED, 4, "denied");
        error(&mut r, 7070);
        let a = Answer::parse(Status::REFUSED, r.as_bytes()).expect("refusal with error");
        assert_eq!(a.fail_error(), 7070);
        assert_eq!(
            a.fail_fact(FACT_RETRY_AFTER_S),
            None,
            "facts are FAILED-only"
        );
        let mut r = fail(Status::FAILED, 7, "the backend said 503");
        error(&mut r, 65_607);
        fact(&mut r, FACT_RETRY_AFTER_S, 30);
        fact(&mut r, FACT_BACKEND_STATUS, 503);
        let a = Answer::parse(Status::FAILED, r.as_bytes()).expect("the full tail");
        assert_eq!(a.fail_error(), 65_607, "raw, never narrowed");
        assert_eq!(a.fail_fact(FACT_RETRY_AFTER_S), Some(30));
        assert_eq!(a.fail_fact(FACT_BACKEND_STATUS), Some(503));
        assert_eq!(a.fail_fact(99), None);
        let mut r = fail(Status::FAILED, 7, "");
        fact(&mut r, FACT_BACKEND_STATUS, 500);
        let a = Answer::parse(Status::FAILED, r.as_bytes()).expect("facts without error");
        assert_eq!(
            (a.fail_error(), a.fail_fact(FACT_BACKEND_STATUS)),
            (0, Some(500))
        );
    }

    #[test]
    fn the_fail_tail_rejected_forms() {
        let bad = |status: Status, build: &dyn Fn(&mut Reply)| {
            let mut r = fail(status, 1, "x");
            build(&mut r);
            Answer::parse(status, r.as_bytes()).err()
        };
        let out_of_place = |t: u16| Some(FaultReason::BadRecords(RecErr::Unknown(t)));
        assert_eq!(
            bad(Status::FAILED, &|r| {
                fact(r, FACT_RETRY_AFTER_S, 1);
                error(r, 5);
            }),
            out_of_place(tag::ERROR),
            "ERROR after a FACT"
        );
        assert_eq!(
            bad(Status::FAILED, &|r| {
                error(r, 5);
                error(r, 6);
            }),
            out_of_place(tag::ERROR),
            "a second ERROR"
        );
        assert_eq!(
            bad(Status::REFUSED, &|r| fact(r, FACT_RETRY_AFTER_S, 1)),
            out_of_place(tag::FACT),
            "a FACT on REFUSED"
        );
        assert_eq!(
            bad(Status::FAILED, &|r| {
                fact(r, FACT_RETRY_AFTER_S, 1);
                fact(r, FACT_RETRY_AFTER_S, 2);
            }),
            out_of_place(tag::FACT),
            "a repeated fact key"
        );
        assert_eq!(
            bad(Status::FAILED, &|r| fact(r, 3, 1)),
            out_of_place(tag::FACT),
            "a key outside FAIL_FACT_KEYS"
        );
        assert_eq!(
            bad(Status::FAILED, &|r| r.put(tag::TEXT, b"t").expect("text")),
            out_of_place(tag::TEXT),
            "any other record"
        );
        assert_eq!(
            Answer::parse(Status::REFUSED, &[]).err(),
            Some(FaultReason::MissingFail)
        );
        let mut r = Reply::new();
        r.put(tag::TEXT, b"t").expect("text");
        assert_eq!(
            Answer::parse(Status::REFUSED, r.as_bytes()).err(),
            Some(FaultReason::MissingFail)
        );
        r.put_pod(tag::FAIL, &FailRec { status: 1, code: 1 })
            .expect("fail");
        assert_eq!(
            Answer::parse(Status::REFUSED, r.as_bytes()).err(),
            out_of_place(tag::TEXT),
            "FAIL not first"
        );
        let r = fail(Status::FAILED, 1, "x");
        assert_eq!(
            Answer::parse(Status::REFUSED, r.as_bytes()).err(),
            Some(FaultReason::BadStatus(Status::FAILED.0)),
            "the FAIL record disagrees with the status"
        );
        let mut r = Reply::new();
        r.put_pod_tail(tag::FAIL, &FailRec { status: 1, code: 1 }, &[0xFF, 0xFE])
            .expect("fail");
        assert_eq!(
            Answer::parse(Status::REFUSED, r.as_bytes()).err(),
            Some(FaultReason::BadRecords(RecErr::Utf8))
        );
        let long = "x".repeat(FAIL_TEXT_WIRE_MAX + 1);
        let r = fail(Status::REFUSED, 1, &long);
        assert_eq!(
            Answer::parse(Status::REFUSED, r.as_bytes()).err(),
            Some(FaultReason::BadRecords(RecErr::Size))
        );
    }

    #[test]
    fn statuses_that_are_not_terminal_answers() {
        assert_eq!(
            Answer::parse(Status::NEED, &[]).err(),
            Some(FaultReason::NeedOutsideAsync)
        );
        assert_eq!(
            Answer::parse(Status::FAULT, &[]).err(),
            Some(FaultReason::Panic)
        );
        assert_eq!(
            Answer::parse(Status(9), &[]).err(),
            Some(FaultReason::BadStatus(9))
        );
    }

    #[test]
    fn an_owned_answer_reborrows_its_validated_layout() {
        let mut buf = Pool::global().acquire(1 << 20);
        let r = {
            let mut r = fail(Status::FAILED, 7, "down");
            error(&mut r, 42);
            fact(&mut r, FACT_RETRY_AFTER_S, 9);
            r
        };
        crate::records::RawWrite::room(&mut buf, r.len()).expect("room");
        crate::records::RawWrite::append(&mut buf, r.as_bytes());
        let owned = OwnedAnswer::new(Status::FAILED, buf).expect("valid");
        let a = owned.answer();
        assert_eq!(a.fail(), Some((7, "down")));
        assert_eq!(
            (a.fail_error(), a.fail_fact(FACT_RETRY_AFTER_S)),
            (42, Some(9))
        );
        let bad = Pool::global().acquire(1 << 20);
        assert_eq!(
            OwnedAnswer::new(Status::REFUSED, bad).err(),
            Some(FaultReason::MissingFail)
        );
    }

    #[test]
    fn metrics_are_decoded_all_or_nothing() {
        let mut r = Reply::new();
        r.put_metric(1, 1, 2.0, &["a", "b"]).expect("metric");
        r.put(tag::TEXT, b"other").expect("text");
        r.put_metric(2, 2, 3.5, &[]).expect("metric");
        let a = Answer::parse(Status::OK, r.as_bytes()).expect("valid");
        let mut seen = Vec::new();
        decode_metrics(&a, &mut |m| {
            seen.push((
                m.id,
                m.op,
                m.value,
                m.labels().map(str::to_owned).collect::<Vec<_>>(),
            ))
        })
        .expect("well formed");
        assert_eq!(
            seen,
            [
                (1, 1, 2.0, vec![String::from("a"), String::from("b")]),
                (2, 2, 3.5, Vec::new())
            ]
        );
        let mut r = Reply::new();
        r.put_metric(1, 1, 2.0, &["ok"]).expect("metric");
        r.put_nested(tag::METRIC, |n| {
            n.put(
                tag::TEXT,
                MetricObs {
                    id: 2,
                    op: 1,
                    value: 1.0,
                }
                .as_bytes(),
            )
        })
        .expect("malformed metric");
        let a = Answer::parse(Status::OK, r.as_bytes()).expect("framing is fine");
        let mut calls = 0;
        assert!(decode_metrics(&a, &mut |_| calls += 1).is_err());
        assert_eq!(calls, 0, "nothing recorded when one METRIC is malformed");
        let refused = fail(Status::REFUSED, 1, "no");
        let a = Answer::parse(Status::REFUSED, refused.as_bytes()).expect("valid");
        assert_eq!(decode_metrics(&a, &mut |_| calls += 1), Ok(()));
        assert_eq!(calls, 0);
    }
}
