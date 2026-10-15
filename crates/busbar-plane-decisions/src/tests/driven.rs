use super::*;
use crate::meta::CLASS_DECISION;

#[test]
fn systemone_arrives_as_the_first_op_class_with_a_principal() {
    let a = arrive("POST", ops::PATH_SYSTEMONE).expect("systemone is claimed");
    assert_eq!(a.op, ops::OP_SYSTEMONE);
    assert_eq!(a.op_class, 0);
    assert_eq!(tail::OP_CLASSES[a.op_class as usize], ops::OP_SYSTEMONE);
    assert_eq!(a.principal, PrincipalNeed::Required);
    assert_eq!(tail::DIALECTS[a.dialect as usize], "jev");
    let e = arrive("POST", ops::PATH_EVALUATE).expect("evaluate is claimed");
    assert_eq!(e.op, ops::OP_EVALUATE);
    assert_eq!(tail::OP_CLASSES[e.op_class as usize], ops::OP_EVALUATE);
    assert_eq!(tail::DIALECTS[e.dialect as usize], "nanojev");
}

#[test]
fn models_is_not_claimed() {
    assert_eq!(arrive("GET", ops::PATH_MODELS), None);
    assert!(!tail::CLAIMS.iter().any(|(_, t, _)| *t == ops::PATH_MODELS));
    assert!(!tail::OP_CLASSES.contains(&ops::OP_MODELS));
}

#[test]
fn an_unknown_request_is_not_claimed() {
    assert_eq!(arrive("GET", ops::PATH_SYSTEMONE), None);
    assert_eq!(arrive("POST", "/v1/elsewhere"), None);
}

#[test]
fn every_claim_arrives() {
    for (verb, target, dialect) in tail::CLAIMS {
        let a = arrive(verb, target).unwrap_or_else(|| panic!("{verb} {target}"));
        assert_eq!(a.dialect, *dialect, "{verb} {target}");
        assert_eq!(attempt_request(*dialect, b"{}").target, *target);
    }
}

/// RED (audit plane-decisions#5): THE DESIGN section 7, "its card prices `decision`, `input_tokens`
/// and `output_tokens` (family `decision`, all three required, 0 = free)".
#[test]
fn the_tail_names_the_decision_class_at_its_index() {
    let (class, family) = tail::BILLABLE_CLASSES[tail::CLASS_DECISION_INDEX as usize];
    assert_eq!(class, CLASS_DECISION);
    assert_eq!(family, "decision");
    for (index, name) in [
        (tail::CLASS_INPUT_TOKENS_INDEX, "input_tokens"),
        (tail::CLASS_OUTPUT_TOKENS_INDEX, "output_tokens"),
    ] {
        let (class, family) = tail::BILLABLE_CLASSES[index as usize];
        assert_eq!((class.as_str(), family), (name, "decision"));
    }
    assert_eq!(tail::BILLABLE_CLASSES.len(), 4);
    // The request fee is the one fee unit, and it is a class at its own index.
    assert_eq!(tail::FEE_UNITS, &[busbar_contract::plane::PER_REQUEST]);
    let (fee, fee_family) = tail::BILLABLE_CLASSES[tail::CLASS_FEE_INDEX as usize];
    assert_eq!(fee.as_str(), tail::FEE_PER_REQUEST);
    assert_eq!(fee_family, tail::FEE_FAMILY);
    assert_eq!(tail::SECTION_DECLARING, crate::config::SECTION);
    assert_eq!(tail::NEEDS, &[(crate::claims::TRANSPORT, "bearer")]);
    assert_eq!(tail::DIALECT_AUTH, &[(0, "bearer"), (1, "bearer")]);
    assert_eq!(tail::DIALECTS, &["jev", "nanojev"]);
}

#[test]
fn the_caller_body_is_kept_and_an_empty_one_is_refused() {
    assert_eq!(caller_piece(b"{\"state\":{}}", true), CallerAnswer::Keep);
    assert_eq!(caller_piece(b"", false), CallerAnswer::Keep);
    assert_eq!(caller_piece(b"", true), CallerAnswer::Empty);
}

#[test]
fn an_attempt_forwards_the_caller_body_unchanged() {
    let body = br#"{"state":{"session":"s"},"context":{}}"#;
    let r = attempt_request(tail::DIALECT_JEV, body);
    assert_eq!(r.verb, "POST");
    assert_eq!(r.target, "/v1/systemone");
    assert_eq!(r.fields, [("content-type", &b"application/json"[..])]);
    assert_eq!(r.auth, "decision-egress");
    assert!(
        std::ptr::eq(r.body, &body[..]),
        "the body is borrowed, not copied"
    );
}

/// The answer's counts as `(class, amount)`, for a far end answering `status` with `body`.
fn billed(status: u32, body: &[u8]) -> Result<Vec<(u32, u64)>, UnreadableUsage> {
    let mut reading = FarEndReading::new();
    reading.piece(body);
    reading.counts(Some(status)).map(|c| {
        c.into_iter()
            .flatten()
            .map(|u| (u.class, u.amount))
            .collect()
    })
}

const DECISION: u32 = tail::CLASS_DECISION_INDEX;
const FEE: u32 = tail::CLASS_FEE_INDEX;
const INPUT: u32 = tail::CLASS_INPUT_TOKENS_INDEX;
const OUTPUT: u32 = tail::CLASS_OUTPUT_TOKENS_INDEX;

#[test]
fn far_end_pieces_are_relayed_unchanged_and_the_count_read_over_the_whole_answer() {
    let mut reading = FarEndReading::new();
    let a = br#"{"request_id":"req_1","usage":{"un"#;
    let b = br#"its":42},"answers":{"decision":"approve"}}"#;
    assert_eq!(reading.piece(a), &a[..]);
    assert_eq!(reading.piece(b), &b[..]);
    let counts = reading.counts(Some(200)).expect("a whole count");
    assert_eq!(
        counts[0],
        Some(Units {
            class: DECISION,
            reported: true,
            amount: 42
        })
    );
}

#[test]
fn an_error_answer_bills_nothing() {
    assert_eq!(
        billed(
            200,
            br#"{"error":{"code":"invalid_state"},"usage":{"units":3}}"#
        ),
        Ok(vec![])
    );
}

/// RED (audit plane-decisions#4): THE DESIGN section 7, "bills one `decision` per successful, settled
/// answer from every provider ... the hosted provider keeps 1.5.5's `/usage/units` as the decision
/// count". A success with no count bills one decision; one with a whole count bills the count.
#[test]
fn a_success_bills_one_decision_or_the_count_it_reports() {
    assert_eq!(billed(200, br#"{}"#), Ok(vec![(DECISION, 1), (FEE, 1)]));
    assert_eq!(
        billed(200, br#"{"usage":{}}"#),
        Ok(vec![(DECISION, 1), (FEE, 1)])
    );
    assert_eq!(
        billed(201, br#"{"usage":{"units":3}}"#),
        Ok(vec![(DECISION, 3), (FEE, 1)])
    );
    assert_eq!(
        billed(200, br#"{"usage":{"units":3},"error":null}"#),
        Ok(vec![(DECISION, 3), (FEE, 1)]),
        "a null error is no error"
    );
    let max = format!(r#"{{"usage":{{"units":{}}}}}"#, i64::MAX);
    assert_eq!(
        billed(200, max.as_bytes()),
        Ok(vec![(DECISION, i64::MAX as u64), (FEE, 1)])
    );
}

/// RED (audit plane-decisions#4): one success rule for every count: a non-2xx answer bills nothing,
/// whatever usage it carries.
#[test]
fn a_non_success_bills_nothing() {
    for status in [400, 422, 500, 503] {
        assert_eq!(
            billed(status, br#"{"usage":{"units":2}}"#),
            Ok(vec![]),
            "{status}"
        );
    }
    let mut reading = FarEndReading::new();
    reading.piece(br#"{"usage":{"units":2}}"#);
    assert_eq!(
        reading.counts(None),
        Ok([None; 4]),
        "no status read, no bill"
    );
}

/// RED (audit plane-decisions#4): a success whose usage member is there but is not a whole count
/// fails loudly, naming the member (finding 395 kept: "LOCATED, never dropped"), never a silent 0.
#[test]
fn a_usage_member_that_is_not_a_whole_count_fails_loudly() {
    for units in [
        "-1".to_string(),
        "1.5".to_string(),
        "7.0".to_string(),
        "1e3".to_string(),
        "\"7\"".to_string(),
        "null".to_string(),
        "{}".to_string(),
        (i64::MAX as u64 + 1).to_string(),
        u64::MAX.to_string(),
    ] {
        let body = format!(r#"{{"usage":{{"units":{units}}}}}"#);
        assert_eq!(
            billed(200, body.as_bytes()),
            Err(UnreadableUsage(crate::codec::PTR_USAGE_UNITS)),
            "{body}"
        );
    }
    assert_eq!(
        billed(200, br#"{"usage":{"units":1,"output_tokens":-2}}"#),
        Err(UnreadableUsage(crate::codec::PTR_USAGE_OUTPUT_TOKENS))
    );
}

/// RED (audit plane-decisions#5): the token counts a success reports are billed in their classes.
#[test]
fn a_success_bills_the_tokens_it_reports() {
    assert_eq!(
        billed(
            200,
            br#"{"usage":{"units":2,"input_tokens":12,"output_tokens":5}}"#
        ),
        Ok(vec![(DECISION, 2), (INPUT, 12), (OUTPUT, 5), (FEE, 1)])
    );
    assert_eq!(
        billed(200, br#"{"usage":{"input_tokens":9}}"#),
        Ok(vec![(DECISION, 1), (INPUT, 9), (FEE, 1)])
    );
}

#[test]
fn the_counts_never_read_state_or_answers() {
    assert_eq!(
        billed(
            200,
            br#"{"usage":{"units":7},"state":{"usage":{"units":999}},"answers":{"units":888}}"#
        ),
        Ok(vec![(DECISION, 7), (FEE, 1)])
    );
}

#[test]
fn a_refusal_carries_the_kernel_text_in_the_dialect_shape() {
    assert_eq!(
        refusal_body(403, "the caller may not perform this operation"),
        br#"{"error":{"code":"unsupported_operation","message":"the caller may not perform this operation"}}"#
    );
    assert_eq!(
        refusal_body(401, "no key"),
        br#"{"error":{"code":"invalid_request","message":"no key"}}"#
    );
    assert_eq!(
        refusal_body(404, "no provider"),
        br#"{"error":{"code":"invalid_params","message":"no provider"}}"#
    );
    assert_eq!(
        refusal_body(500, "x"),
        br#"{"error":{"code":"internal","message":"x"}}"#
    );
    assert_eq!(
        refusal_body(503, "x"),
        br#"{"error":{"code":"unsupported_operation","message":"x"}}"#
    );
}

/// RED (audit plane-decisions#1): every generation with a model mounts the claim (THE DESIGN
/// section 2: "more than one and none named is 400", so several models are served); none mounts
/// nothing, and the kernel's unclaimed-route bytes stand.
#[test]
fn one_or_more_models_mount_the_claim() {
    let systemone = ("POST", ops::PATH_SYSTEMONE, tail::DIALECT_JEV);
    let evaluate = ("POST", ops::PATH_EVALUATE, tail::DIALECT_NANOJEV);
    assert!(served_claims(&[]).is_empty());
    assert_eq!(served_claims(&[0]), vec![systemone]);
    assert_eq!(served_claims(&[0, 0]), vec![systemone]);
    assert_eq!(served_claims(&[1]), vec![evaluate]);
    assert_eq!(served_claims(&[1, 0, 1]), vec![systemone, evaluate]);
    assert_eq!(dialect_of("nanojev"), Some(tail::DIALECT_NANOJEV));
    assert_eq!(dialect_of("anthropic"), None);
}

fn models(names: &[&str]) -> std::collections::BTreeMap<String, ()> {
    names.iter().map(|n| ((*n).to_string(), ())).collect()
}

/// MODEL RESOLUTION (THE DESIGN section 2): the named model; one configured and none named is the
/// default; several and none named, or a `model` that is not a string, is 400; an unknown name 404.
#[test]
fn a_request_routes_over_the_model_it_names() {
    let two = models(&["a", "b"]);
    assert_eq!(
        route_model(br#"{"model":"b"}"#, &two, |_| true).map(|r| r.0),
        Ok("b")
    );
    assert_eq!(
        route_model(br#"{"model":"\u0061"}"#, &two, |_| true).map(|r| r.0),
        Ok("a"),
        "an escaped name is the name it spells"
    );
    assert_eq!(
        route_model(br#"{"state":{}}"#, &two, |_| true),
        Err(Unrouted::Unnamed)
    );
    assert_eq!(
        route_model(br#"{"model":"zz"}"#, &two, |_| true),
        Err(Unrouted::Unknown("zz".to_string()))
    );
    assert_eq!(
        route_model(br#"{"model":null}"#, &two, |_| true),
        Err(Unrouted::NotAName)
    );
    assert_eq!(
        route_model(br#"{"model":["a"]}"#, &two, |_| true),
        Err(Unrouted::NotAName)
    );
    // A nested `model` is not the request's.
    assert_eq!(
        route_model(br#"{"state":{"model":"a"}}"#, &two, |_| true),
        Err(Unrouted::Unnamed)
    );

    let one = models(&["jev"]);
    assert_eq!(
        route_model(br#"{"state":{}}"#, &one, |_| true).map(|r| r.0),
        Ok("jev")
    );
    assert_eq!(
        route_model(b"not json", &one, |_| true).map(|r| r.0),
        Ok("jev")
    );
    assert_eq!(
        route_model(br#"{"model":"other"}"#, &one, |_| true),
        Err(Unrouted::Unknown("other".to_string()))
    );
    assert_eq!(
        route_model(br#"{}"#, &models(&[]), |_| true),
        Err(Unrouted::Unnamed)
    );

    assert_eq!(
        (Unrouted::Unnamed.status(), Unrouted::NotAName.status()),
        (400, 400)
    );
    assert_eq!(Unrouted::Unknown("zz".to_string()).status(), 404);
}

/// THE `upstream_model` SPLICE (THE DESIGN section 2): the top-level value alone, when it differs.
#[test]
fn the_splice_rewrites_the_top_level_model_value_alone() {
    let body = br#"{"model" : "jev", "state":{"model":"jev"}}"#;
    assert_eq!(
        spliced(body, "jev-1.13.0").as_deref(),
        Some(&br#"{"model" : "jev-1.13.0", "state":{"model":"jev"}}"#[..])
    );
    assert_eq!(spliced(body, "jev"), None, "the same name passes through");
    assert_eq!(
        spliced(br#"{"state":{}}"#, "x"),
        None,
        "no model to rewrite"
    );
    assert_eq!(spliced(br#"{"model":3}"#, "x"), None, "not a name");
    assert_eq!(
        spliced(br#"{"model":"a"}"#, "q\"x").as_deref(),
        Some(&br#"{"model":"q\"x"}"#[..]),
        "the value is written as a JSON string"
    );
}

/// BILLABLE SUCCESS ONLY: the request fee is counted once for a far end's 2xx answer with no
/// `/error` member, and never for an error answer, a non-2xx status or an answer with no status.
#[test]
fn the_request_fee_is_counted_on_a_success_alone() {
    let mut ok = FarEndReading::new();
    ok.piece(br#"{"usage":{"units":3}}"#);
    let fee = ok.counts(Some(200)).expect("a success")[3].expect("a success owes its fee");
    assert_eq!((fee.class, fee.amount, fee.reported), (FEE, 1, true));
    // RED ARMS.
    assert_eq!(
        ok.counts(Some(422)),
        Ok([None; 4]),
        "a refused request owes none"
    );
    assert_eq!(ok.counts(Some(500)), Ok([None; 4]));
    assert_eq!(ok.counts(None), Ok([None; 4]), "no status read, no fee");
    assert_eq!(
        billed(200, br#"{"error":{"code":"x","message":"y"}}"#),
        Ok(vec![]),
        "an error answer owes none"
    );
}

/// THE CALLER'S FIELDS REACH THE FAR END (DEC-SERVE Q2, DIALECT-FIDELITY F2): every one, in order,
/// a repeated name keeping each value, but the governed set (the document type the plane writes, the
/// hop's `host`, the credential carriers), compared without case.
#[test]
fn every_caller_field_but_the_governed_set_is_relayed() {
    let caller: [(&[u8], &[u8]); 7] = [
        (b"X-Trace", b"a"),
        (b"Authorization", b"Bearer caller-key"),
        (b"content-type", b"text/plain"),
        (b"Host", b"busbar.example"),
        (b"x-trace", b"b"),
        (b"Proxy-Authorization", b"Basic x"),
        (b"accept-language", b"en"),
    ];
    let kept = relayed_fields(caller);
    assert_eq!(
        kept.iter()
            .map(|(n, v)| (n.to_vec(), v.to_vec()))
            .collect::<Vec<_>>(),
        vec![
            (b"x-trace".to_vec(), b"a".to_vec()),
            (b"x-trace".to_vec(), b"b".to_vec()),
            (b"accept-language".to_vec(), b"en".to_vec()),
        ]
    );
    assert!(relayed_fields(std::iter::empty()).is_empty());
}

/// The money rule's reading of a whole answer by its declared pointers, as the body would be read
/// kept whole: the reference the piece-by-piece reading is held to.
fn by_pointer(status: u32, body: &[u8]) -> Result<Vec<(u32, u64)>, UnreadableUsage> {
    use crate::codec::{read_raw, PTR_ERROR};
    let ok = (200..300).contains(&status) && read_raw(body, PTR_ERROR).is_none_or(|e| e == b"null");
    if !ok {
        return Ok(vec![]);
    }
    let count = |p: &'static str| match read_raw(body, p) {
        None => Ok(None),
        Some(raw) => whole(raw).map(Some).ok_or(UnreadableUsage(p)),
    };
    let mut out = vec![(DECISION, count(crate::codec::PTR_USAGE_UNITS)?.unwrap_or(1))];
    if let Some(n) = count(crate::codec::PTR_USAGE_INPUT_TOKENS)? {
        out.push((INPUT, n));
    }
    if let Some(n) = count(crate::codec::PTR_USAGE_OUTPUT_TOKENS)? {
        out.push((OUTPUT, n));
    }
    out.push((FEE, 1));
    Ok(out)
}

/// The answer read in two pieces split at `at`.
fn split_billed(status: u32, body: &[u8], at: usize) -> Result<Vec<(u32, u64)>, UnreadableUsage> {
    let mut reading = FarEndReading::new();
    reading.piece(&body[..at]);
    reading.piece(&body[at..]);
    reading.counts(Some(status)).map(|c| {
        c.into_iter()
            .flatten()
            .map(|u| (u.class, u.amount))
            .collect()
    })
}

/// RED (audit plane-decisions#8): the answer is read as it passes, in fixed space, wherever the
/// pieces split it, and reads exactly what the declared pointers read over the whole answer.
#[test]
fn the_reading_is_the_pointers_reading_wherever_the_pieces_split() {
    let answers: [&[u8]; 14] = [
        br#"{"request_id":"req_1","usage":{"units":42},"answers":{"decision":"approve"}}"#,
        br#" { "usage" : { "input_tokens" : 12 , "units" : 3, "output_tokens":5 } } "#,
        br#"{"answers":{"usage":{"units":9}},"usage":{"units":2}}"#,
        br#"{"state":{"error":"x","usage":{"units":"q"}},"usage":{}}"#,
        br#"{"error":null,"usage":{"units":7}}"#,
        br#"{"error":{"code":"x","message":"y"},"usage":{"units":3}}"#,
        br#"{"error":"down"}"#,
        br#"{"usage":{"units":7.5}}"#,
        br#"{"usage":{"units":"7"}}"#,
        br#"{"usage":{"units":[1]}}"#,
        br#"{"usage":{"units":99999999999999999999999999}}"#,
        br#"{"a\"usage":{"units":"no"},"usage":{"output_tokens":-1}}"#,
        br#"{"usage":"n/a","x":[{"usage":{"units":1}}]}"#,
        br#"[{"usage":{"units":5}}]"#,
    ];
    for body in answers {
        for status in [200, 500] {
            let want = by_pointer(status, body);
            for at in 0..=body.len() {
                assert_eq!(
                    split_billed(status, body, at),
                    want,
                    "{status} {} split at {at}",
                    String::from_utf8_lossy(body)
                );
            }
        }
    }
}

/// An answer of any size is read in the reading's own fixed space.
#[test]
fn a_large_answer_is_read_without_keeping_it() {
    let mut reading = FarEndReading::new();
    let before = std::mem::size_of_val(&reading);
    reading.piece(br#"{"answers":{"blob":""#);
    let filler = [b'x'; 4096];
    for _ in 0..256 {
        reading.piece(&filler);
    }
    reading.piece(br#""},"usage":{"units":4}}"#);
    assert_eq!(std::mem::size_of_val(&reading), before);
    assert_eq!(
        reading.counts(Some(200)).map(|c| c[0].map(|u| u.amount)),
        Ok(Some(4))
    );
}

/// The counts of a `nanojev` answer, `(class, amount)`.
fn nanojev_billed(status: u32, body: &[u8]) -> Result<Vec<(u32, u64)>, UnreadableUsage> {
    let mut reading = FarEndReading::for_dialect(tail::DIALECT_NANOJEV);
    reading.piece(body);
    reading.counts(Some(status)).map(|c| {
        c.into_iter()
            .flatten()
            .map(|u| (u.class, u.amount))
            .collect()
    })
}

/// RED (audit plane-decisions#3): THE DESIGN section 2, NanoJev "meters the upstream's own billing
/// unit, counted from the answer already read (`execution.states`; an answer with no count refuses
/// loudly". Its answer is read by its own pointer, never jev's.
#[test]
fn a_nanojev_answer_bills_its_execution_states() {
    assert_eq!(
        nanojev_billed(200, br#"{"execution":{"states":3},"result":{}}"#),
        Ok(vec![(DECISION, 3), (FEE, 1)])
    );
    assert_eq!(
        nanojev_billed(
            200,
            br#"{"usage":{"units":9,"input_tokens":4},"execution":{"states":1}}"#
        ),
        Ok(vec![(DECISION, 1), (FEE, 1)]),
        "jev's usage members are not nanojev's"
    );
    for missing in [
        &br#"{"result":{}}"#[..],
        br#"{"execution":{}}"#,
        br#"{"usage":{"units":2}}"#,
    ] {
        assert_eq!(
            nanojev_billed(200, missing),
            Err(UnreadableUsage(crate::codec::PTR_EXECUTION_STATES)),
            "{}",
            String::from_utf8_lossy(missing)
        );
    }
    assert_eq!(
        nanojev_billed(200, br#"{"execution":{"states":2.5}}"#),
        Err(UnreadableUsage(crate::codec::PTR_EXECUTION_STATES))
    );
    assert_eq!(
        nanojev_billed(500, br#"{"result":{}}"#),
        Ok(vec![]),
        "a failure bills nothing"
    );
    // Wherever the pieces split it.
    let body = br#"{"execution" : {"trace":[{"states":99}], "states" : 12}}"#;
    for at in 0..=body.len() {
        let mut reading = FarEndReading::for_dialect(tail::DIALECT_NANOJEV);
        reading.piece(&body[..at]);
        reading.piece(&body[at..]);
        assert_eq!(
            reading.counts(Some(200)).map(|c| c[0].map(|u| u.amount)),
            Ok(Some(12)),
            "split at {at}"
        );
    }
}

/// RED (audit plane-decisions#3): a request routes among its claim's dialect's models; a model of
/// the other dialect is this dialect's unknown model, and one model of the dialect is its default.
#[test]
fn a_model_of_the_other_dialect_is_this_dialects_unknown_model() {
    let models: std::collections::BTreeMap<String, u32> =
        [("j".to_string(), 0), ("n".to_string(), 1)].into();
    let jev = |d: &u32| *d == tail::DIALECT_JEV;
    let nano = |d: &u32| *d == tail::DIALECT_NANOJEV;
    assert_eq!(
        route_model(br#"{"model":"n"}"#, &models, jev),
        Err(Unrouted::Unknown("n".to_string()))
    );
    assert_eq!(
        route_model(br#"{"model":"n"}"#, &models, nano).map(|r| r.0),
        Ok("n")
    );
    assert_eq!(route_model(br#"{}"#, &models, jev).map(|r| r.0), Ok("j"));
    assert_eq!(route_model(br#"{}"#, &models, nano).map(|r| r.0), Ok("n"));
}
