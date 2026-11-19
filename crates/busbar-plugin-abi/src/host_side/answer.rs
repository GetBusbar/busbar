// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-side answers and the one METRIC decoder (IF §10.2, §12.17; W1-H1).
//!
//! An `Answer` exists only for a validated terminal answer: `Answer::parse` (and `OwnedAnswer::new`, which
//! keeps the validated layout beside its buffer) walks the records once and refuses anything the generic
//! layer can already judge. OK: a framing error is FAULT BadRecords; FAIL, NEED, NEED_RES, ERROR, the retired
//! 0x000A, a TOKEN anywhere but first, a DIRECTORY-only nested tag at top level, an undefined generic tag and
//! any tag above the kind range are FAULT UnknownTag (kind tags 0x0100..=0x01FF pass to the kind decoder).
//! REFUSED/FAILED: exactly FAIL, at most one ERROR directly after it, then (FAILED only) at most two FACTs with
//! distinct keys in `FAIL_FACT_KEYS`; anything else is FAULT BadRecords. NEED is not an answer
//! (NeedOutsideAsync), FAULT is the shim's caught panic or broken contract (Panic) and any other status is
//! BadStatus.

use zerocopy::FromBytes;

use crate::fail::{FAIL_FACT_KEYS, FAIL_TEXT_WIRE_MAX, FaultReason};
use crate::host_side::pool::PooledOut;
use crate::records::{FactRec, FailRec, MetricObs, RecErr, RecHead, Records, U32Rec, tag};
use crate::types::Status;

/// Where a validated answer's parts lie in its bytes (offsets, so an `OwnedAnswer` re-borrows them in O(1)).
#[derive(Clone, Copy, Debug, Default)]
struct Layout {
    /// OK: where the records start (after a leading TOKEN). REFUSED/FAILED: the end (no records).
    at: usize,
    /// REFUSED/FAILED: (code, text start, text length).
    fail: Option<(u32, usize, usize)>,
    error: u32,
    facts: [Option<u64>; 2],
}

/// The bytes one record takes: head, body, zero padding to 8.
fn record_size(body: usize) -> usize {
    size_of::<RecHead>() + body.div_ceil(8) * 8
}

/// Whether a generic tag (below the kind range) may stand at the top level of an OK answer. Kind tags
/// (0x0100..=0x01FF) are the kind decoder's; FAIL/NEED/NEED_RES/ERROR, 0x000A and the DIRECTORY nested tags
/// never stand there; TOKEN only first (a session opener's).
fn ok_generic(t: u16) -> bool {
    matches!(
        t,
        tag::TEXT
            | tag::FACT
            | tag::FACT_TEXT
            | tag::PAIR
            | tag::INSTANCE
            | tag::CONFIG
            | tag::CORE_CFG
            | tag::H_METHOD..=tag::H_BODY_LEN
            | tag::CONVERSATION
            | tag::D_METHODS..=tag::D_ERRORS
            | tag::ID_SUBJECT..=tag::ID_CLAIM
            | tag::METRIC
            | tag::REC_PRED..=tag::REC_DEL
            | tag::ENDPOINT
    )
}

fn layout_ok(bytes: &[u8]) -> Result<Layout, FaultReason> {
    let mut layout = Layout::default();
    for (i, rec) in Records::new(bytes).enumerate() {
        let rec = rec.map_err(FaultReason::BadRecords)?;
        match rec.tag {
            tag::TOKEN if i == 0 => layout.at = record_size(rec.body.len()),
            // The kind ranges (interface revision D.2): 0x0100..=0x01FF, extended to 0x4FFF. Which of
            // them a kind declares, and which it has retired, is the kind decoder's to judge.
            0x0100..=0x4FFF => {}
            t if t < 0x0100 && !tag::RETIRED.contains(&t) && ok_generic(t) => {}
            t => return Err(FaultReason::UnknownTag(t)),
        }
    }
    Ok(layout)
}

fn layout_fail(status: Status, bytes: &[u8]) -> Result<Layout, FaultReason> {
    let failed = status == Status::FAILED;
    let mut recs = Records::new(bytes);
    let Some(first) = recs.next() else {
        return Err(FaultReason::MissingFail);
    };
    let first = first.map_err(FaultReason::BadRecords)?;
    if first.tag != tag::FAIL {
        let fail_later = recs.any(|rec| rec.is_ok_and(|rec| rec.tag == tag::FAIL));
        return Err(if fail_later {
            FaultReason::BadRecords(RecErr::Unknown(first.tag))
        } else {
            FaultReason::MissingFail
        });
    }
    let (head, text) = first
        .pod_tail::<FailRec>()
        .map_err(FaultReason::BadRecords)?;
    if head.status != status.0 {
        return Err(FaultReason::BadStatus(head.status));
    }
    if text.len() > FAIL_TEXT_WIRE_MAX {
        return Err(FaultReason::BadRecords(RecErr::Size));
    }
    core::str::from_utf8(text).map_err(|_| FaultReason::BadRecords(RecErr::Utf8))?;
    let start = text.as_ptr().addr() - bytes.as_ptr().addr();
    let mut layout = Layout {
        at: bytes.len(),
        fail: Some((head.code, start, text.len())),
        error: 0,
        facts: [None; 2],
    };
    let mut seen_error = false;
    let mut seen_fact = false;
    for rec in recs {
        let rec = rec.map_err(FaultReason::BadRecords)?;
        let out_of_place = FaultReason::BadRecords(RecErr::Unknown(rec.tag));
        match rec.tag {
            tag::ERROR if !seen_error && !seen_fact => {
                let error = rec.pod::<U32Rec>().map_err(FaultReason::BadRecords)?;
                if error._r != 0 {
                    return Err(FaultReason::BadRecords(RecErr::Reserved));
                }
                layout.error = error.value;
                seen_error = true;
            }
            tag::FACT if failed => {
                let fact = rec.pod::<FactRec>().map_err(FaultReason::BadRecords)?;
                if fact._r != 0 {
                    return Err(FaultReason::BadRecords(RecErr::Reserved));
                }
                let slot = FAIL_FACT_KEYS
                    .iter()
                    .position(|&key| key == fact.key)
                    .and_then(|at| layout.facts.get_mut(at))
                    .ok_or(out_of_place)?;
                if slot.replace(fact.value).is_some() {
                    return Err(out_of_place);
                }
                seen_fact = true;
            }
            _ => return Err(out_of_place),
        }
    }
    Ok(layout)
}

fn layout(status: Status, bytes: &[u8]) -> Result<Layout, FaultReason> {
    match status {
        Status::OK => layout_ok(bytes),
        Status::REFUSED | Status::FAILED => layout_fail(status, bytes),
        Status::NEED => Err(FaultReason::NeedOutsideAsync),
        Status::FAULT => Err(FaultReason::Panic),
        Status(other) => Err(FaultReason::BadStatus(other)),
    }
}

pub struct Answer<'o> {
    pub status: Status,
    recs: Records<'o>,
    fail: Option<(u32, &'o str)>,
    error: u32,
    facts: [Option<u64>; 2],
}
impl<'o> Answer<'o> {
    /// Validates a terminal answer (module doc) and borrows it. Every proxy and the driver build answers here.
    pub fn parse(status: Status, bytes: &'o [u8]) -> Result<Answer<'o>, FaultReason> {
        Ok(Answer::at(status, bytes, layout(status, bytes)?))
    }

    fn at(status: Status, bytes: &'o [u8], layout: Layout) -> Answer<'o> {
        let fail = layout.fail.map(|(code, start, len)| {
            let text = bytes
                .get(start..start + len)
                .and_then(|text| core::str::from_utf8(text).ok())
                .unwrap_or("");
            (code, text)
        });
        Answer {
            status,
            recs: Records::new(bytes.get(layout.at..).unwrap_or(&[])),
            fail,
            error: layout.error,
            facts: layout.facts,
        }
    }

    /// OK: the answer records, excluding a leading TOKEN record. REFUSED/FAILED: empty (the answer is exactly
    /// one FAIL record, §6.4 step 2; round 21: on FAILED, followed by ≤ 2 FACT records with distinct keys in
    /// `FAIL_FACT_KEYS`, validated when the answer is built; any other record next to FAIL is FAULT BadRecords).
    /// Round 34: the validated tail is FAIL, at most one ERROR directly after it (REFUSED or FAILED), then the
    /// FAILED-only FACTs; a second ERROR or one after a FACT is FAULT BadRecords, and ERROR in an OK or NEED
    /// answer is FAULT UnknownTag (§3).
    pub fn records(&self) -> Records<'o> {
        self.recs
    }
    /// Round 21: a fact a FAILED answer carried after FAIL (`FACT_RETRY_AFTER_S`, `FACT_BACKEND_STATUS`); None
    /// for OK, REFUSED, or when absent. Read by the one `PortError::Failed` builder every adapter uses.
    pub fn fail_fact(&self, key: u32) -> Option<u64> {
        let at = FAIL_FACT_KEYS.iter().position(|&known| known == key)?;
        self.facts.get(at).copied().flatten()
    }
    /// Round 34: the ERROR number a REFUSED or FAILED answer carried after FAIL, as the raw `u32` it arrived as
    /// (0 = none, also for OK). Never narrowed here: the shared `PortError`/`OpenError` builder resolves it
    /// through the image's `ErrorBook` (§11.2), which treats anything above 9999 as not declared.
    pub fn fail_error(&self) -> u32 {
        self.error
    }
    /// (code, text) for REFUSED or FAILED. The text is re-validated as UTF-8 and is **not cut** by the host
    /// (round 15: it is ≤ `FAIL_TEXT_WIRE_MAX`, the shim's wire bound). It is the plugin's raw text: adapters pass
    /// it through `scrub::fail_text` (§12.16: scrub, mask a trailing partial needle, then cut to 512) before it
    /// becomes a `PortError` text, a log line or an audit field; no core path cuts it before that call.
    pub fn fail(&self) -> Option<(u32, &'o str)> {
        self.fail
    }
    // W1-H1: `pub(crate) fn session_token(&self) -> Option<Token>` (IF §10.2: the session token a session
    // opener answered with, bit 63 checked; read only by the §10.4 session-handle constructor) is not written:
    // busbar-ffi's `Instance::open_sessionN` reads the leading session TOKEN itself and hands back the `Session`
    // (UNSAFE-MIN §2.2), and a crate-private fn with no caller is dead code. `parse` already accepts a leading
    // TOKEN and keeps it out of `records()`.
    pub fn is_ok(&self) -> bool {
        self.status == Status::OK
    }
}

/// An async answer: owns its pooled buffer.
pub struct OwnedAnswer {
    status: Status,
    buf: PooledOut,
    layout: Layout,
}
impl OwnedAnswer {
    /// Validates the terminal answer in `buf` (as `Answer::parse`) and keeps it; on a FAULT the buffer drops
    /// (zeroed, released).
    pub fn new(status: Status, buf: PooledOut) -> Result<OwnedAnswer, FaultReason> {
        let layout = layout(status, buf.bytes())?;
        Ok(OwnedAnswer {
            status,
            buf,
            layout,
        })
    }
    pub fn answer(&self) -> Answer<'_> {
        Answer::at(self.status, self.buf.bytes(), self.layout)
    }
}

/// One decoded METRIC observation of an answer (§3 `MetricObs` plus its PAIR* label values, keys as declared).
/// W1-H1 freezes the shape the W0 stub left open (with K8's recorder as its one consumer): the Pod fields as
/// they arrived (K8 drops undeclared ids and non-finite values, §3) and the label values, already checked.
#[derive(Clone, Copy)]
pub struct MetricObsIn<'a> {
    pub id: u32,
    pub op: u32,
    pub value: f64,
    labels: Records<'a>,
}
impl<'a> MetricObsIn<'a> {
    /// The label values, in declared-key order (each a nested PAIR with an empty name and a UTF-8 value).
    pub fn labels(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.labels
            .filter_map(Result::ok)
            .filter_map(|rec| rec.pair().ok())
            .filter_map(|(_, value)| core::str::from_utf8(value).ok())
    }
}

/// One METRIC body, checked: Pod `MetricObs`, then only nested PAIRs with an empty name and a UTF-8 value.
fn metric(body: &[u8]) -> Result<MetricObsIn<'_>, FaultReason> {
    let (obs, tail) =
        MetricObs::read_from_prefix(body).map_err(|_| FaultReason::BadRecords(RecErr::Size))?;
    let labels = Records::new(tail);
    for rec in labels {
        let rec = rec.map_err(FaultReason::BadRecords)?;
        if rec.tag != tag::PAIR {
            return Err(FaultReason::BadRecords(RecErr::Unknown(rec.tag)));
        }
        let (name, value) = rec.pair().map_err(FaultReason::BadRecords)?;
        if !name.is_empty() {
            return Err(FaultReason::BadRecords(RecErr::Reserved));
        }
        core::str::from_utf8(value).map_err(|_| FaultReason::BadRecords(RecErr::Utf8))?;
    }
    Ok(MetricObsIn {
        id: obs.id,
        op: obs.op,
        value: obs.value,
        labels,
    })
}

/// The one decoder of the generic METRIC records of every kind's answer, into core's recorder (§12.17, §8.8);
/// no adapter decodes them itself. All or nothing: every METRIC record is checked before the first is handed
/// to `f`, so a malformed one (FAULT BadRecords, the plugin broke the §3 shape) records nothing. REFUSED and
/// FAILED answers carry no records, so they record nothing.
pub fn decode_metrics(
    answer: &Answer<'_>,
    f: &mut impl FnMut(MetricObsIn<'_>),
) -> Result<(), FaultReason> {
    let metrics = || {
        answer
            .records()
            .filter_map(Result::ok)
            .filter(|rec| rec.tag == tag::METRIC)
    };
    for rec in metrics() {
        metric(rec.body)?;
    }
    for rec in metrics() {
        f(metric(rec.body)?);
    }
    Ok(())
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
    fn a_describe_answer_may_declare_plane_upstream_registration_paths() {
        // D_UPSTREAM_PATH is the plane's own describe item (plane 2.0; the generic 0x004D is retired).
        let mut r = Reply::new();
        r.put_text(crate::plane::tag::D_UPSTREAM_PATH, "/upstreams/*")
            .expect("path");
        assert!(Answer::parse(Status::OK, r.as_bytes()).is_ok());
        let mut old = Reply::new();
        old.put_text(0x004D, "/upstreams/*").expect("path");
        assert!(
            Answer::parse(Status::OK, old.as_bytes()).is_err(),
            "a retired number is a fault"
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
