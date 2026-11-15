// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plane request encoders and describe decoders (IF §8.8). W0-ABI stub: frozen signatures, `todo!()` bodies;
//! A10 fills it.

use busbar_plugin_abi::records::{Full, RecErr, Records, Writer};
use busbar_plugin_abi::types::Pair;

use crate::ports::plane::{ObservedAnswer, TrustAnswer, WorkAnswer};

/// Round 13: the D_PROVIDER_SCHEMA text (at most one; a second is RecErr), or None.
pub fn decode_provider_schema<'o>(describe: Records<'o>) -> Result<Option<&'o str>, RecErr> {
    let _ = describe;
    todo!()
}

/// Round 15: every D_DIALECT_AUTH item as a typed presentation, in describe order. A dialect not among the
/// image's D_DIALECT items, a second row for one dialect, an unknown presentation word, a field that does
/// not belong to the presentation, a missing DA_SIGN_SERVICE/DA_REGION_DEFAULT under PRESENT_SIGN, or a
/// TEXT outside the charset/length of §8.6 is RecErr (the registry refuses DescribeInvalid). Borrowed; the
/// registry copies it once at `add` into `DialectAuthOwned` (cold).
pub fn decode_dialect_auth<'o>(describe: Records<'o>) -> Result<Vec<DialectAuth<'o>>, RecErr> {
    let _ = describe;
    todo!()
}

/// Round 15: one D_DIALECT_AUTH row. Core vocabulary only: nothing in it is a plugin settings key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialectAuth<'o> {
    pub dialect: &'o str,
    pub present: Presentation<'o>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presentation<'o> {
    Header {
        key_header: Option<&'o str>,
        own_header: Option<&'o str>,
        passthrough_header: Option<&'o str>,
        families: Vec<(
            &'o str, /* prefix */
            &'o str, /* header, "" = bearer */
            bool,    /* trim_start */
        )>,
    },
    Sign {
        service: &'o str,
        region_after: Vec<&'o str>,
        region_default: &'o str,
    },
}

/// The registry's owned copy (every `&'o str` becomes `Box<str>`; same shape, same field names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialectAuthOwned {
    pub dialect: Box<str>,
    pub present: PresentationOwned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresentationOwned {
    Header {
        key_header: Option<Box<str>>,
        own_header: Option<Box<str>>,
        passthrough_header: Option<Box<str>>,
        families: Vec<(Box<str>, Box<str>, bool)>,
    },
    Sign {
        service: Box<str>,
        region_after: Vec<Box<str>>,
        region_default: Box<str>,
    },
}

impl DialectAuth<'_> {
    pub fn to_owned(&self) -> DialectAuthOwned {
        let _ = self;
        todo!()
    }
}

/// The presentation words of D_DIALECT_AUTH (core vocabulary).
pub const PRESENT_HEADER: &str = "header";
pub const PRESENT_SIGN: &str = "request-signature";

/// `code` < 0x100 (generic only, §12.15; a larger code is a core bug: debug_assert, then R_DENIED).
pub fn encode_refusal(w: &mut impl Writer, status: u16, code: u32, text: &str) -> Result<(), Full> {
    let _ = (w, status, code, text);
    todo!()
}

/// FROM_UPSTREAM P_HEAD: H_STATUS, PAIR*, FACT(FACT_TLS_PIN)? and FACT(FACT_TLS_CLIENT_ID)?.
pub fn encode_upstream_head(
    w: &mut impl Writer,
    status: u16,
    headers: &[Pair<'_>],
    pin_ok: Option<bool>,
    client_id: Option<bool>,
) -> Result<(), Full> {
    let _ = (w, status, headers, pin_ok, client_id);
    todo!()
}

/// (check, outcome, failed, status) per COMMIT, in answer order.
pub fn encode_committed(w: &mut impl Writer, answers: &[(u32, u32, u32, u32)]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

pub fn encode_trust_answers(w: &mut impl Writer, answers: &[TrustAnswer<'_>]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

pub fn encode_chan_attach(
    w: &mut impl Writer,
    generation: u64,
    slot: u64,
    greet: bool,
    ready_tail: &[u8],
) -> Result<(), Full> {
    let _ = (w, generation, slot, greet, ready_tail);
    todo!()
}

pub fn encode_catalog(w: &mut impl Writer, models: &[&str]) -> Result<(), Full> {
    let _ = (w, models);
    todo!()
}

pub fn encode_lookup_hits(w: &mut impl Writer, hits: &[(u32, &[u8], &[u8])]) -> Result<(), Full> {
    let _ = (w, hits);
    todo!()
}

/// Round 12: one CHAIN_STATE after the LOOKUP_HITs of an LK_CHAIN lookup (§8.6).
pub fn encode_chain_state(
    w: &mut impl Writer,
    lookup: u32,
    len: u64,
    broken_at: u64,
) -> Result<(), Full> {
    let _ = (w, lookup, len, broken_at);
    todo!()
}

pub fn encode_entitle_answers(w: &mut impl Writer, answers: &[(u32, bool)]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

/// Round 16, P_JUDGED: one JUDGE_ANS (check, verdict = DEST_*) per JUDGE, in intent order.
pub fn encode_judged(w: &mut impl Writer, answers: &[(u32, u32)]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

/// P_OBSERVED: OBS_SCOPE_ANS (check, status, scope id) and OBS_RECEIPT (check, status, receipt), in intent order.
pub fn encode_observed(w: &mut impl Writer, answers: &[ObservedAnswer<'_>]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

/// Round 10, P_WORK: one WORK_ANS per WORK, in intent order (WK_REF for OPEN/FIND, then WK_TARGET for FIND).
pub fn encode_work_answers(w: &mut impl Writer, answers: &[WorkAnswer<'_>]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

#[cfg(test)]
mod tests {
    //! W1-A10: the plane encoders and describe decoders of IF §8.8, read back with the generic reader (§3.1).

    use busbar_plugin_abi::fail::{fact, refused};
    use busbar_plugin_abi::plane::{self, tag};
    use busbar_plugin_abi::records::{
        tag as generic, FactRec, Full, Nested, PairRec, Rec, RecErr, Records, Reply, U32Rec, Writer,
    };
    use busbar_plugin_abi::types::{Bytes, Pair, Str};

    use super::*;
    use crate::ports::plane::TrustItem;

    fn recs(bytes: &[u8]) -> Vec<Rec<'_>> {
        Records::new(bytes)
            .collect::<Result<Vec<_>, _>>()
            .expect("the encoder writes well-framed records")
    }

    fn texts<'a>(records: &[Rec<'a>], want: u16) -> Vec<&'a str> {
        records
            .iter()
            .map(|rec| {
                assert_eq!(rec.tag, want);
                rec.text().expect("UTF-8")
            })
            .collect()
    }

    #[test]
    fn a_refusal_is_one_record_with_its_status_code_and_text() {
        let mut w = Reply::new();
        encode_refusal(&mut w, 403, refused::R_DENIED, "denied by policy").expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, tag::REFUSAL);
        let (head, text) = records[0]
            .pod_tail::<plane::RefusalRec>()
            .expect("RefusalRec");
        assert_eq!((head.status, head.code), (403, refused::R_DENIED));
        assert_eq!(text, b"denied by policy");
    }

    #[test]
    fn a_refusal_status_is_clamped_and_its_text_cut_at_a_char_boundary() {
        let mut long = "a".repeat(299);
        long.push('é'); // bytes 299..301: a 300-byte cut would split it
        let mut w = Reply::new();
        encode_refusal(&mut w, 200, refused::R_INVALID, &long).expect("fits");
        encode_refusal(&mut w, 700, refused::R_INVALID, "").expect("fits");
        let records = recs(w.as_bytes());
        let (low, text) = records[0]
            .pod_tail::<plane::RefusalRec>()
            .expect("RefusalRec");
        assert_eq!(low.status, 400);
        assert_eq!(text, "a".repeat(299).as_bytes());
        let (high, empty) = records[1]
            .pod_tail::<plane::RefusalRec>()
            .expect("RefusalRec");
        assert_eq!(high.status, 599);
        assert!(empty.is_empty());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "generic code")]
    fn a_kind_code_in_a_refusal_is_a_core_bug() {
        let mut w = Reply::new();
        let _ = encode_refusal(&mut w, 403, 0x100, "kind code");
    }

    #[test]
    fn an_upstream_head_is_status_pairs_then_the_tls_facts() {
        let mut w = Reply::new();
        let pairs = [Pair {
            name: Str::EMPTY,
            value: Bytes::EMPTY,
        }];
        encode_upstream_head(&mut w, 201, &pairs, Some(true), Some(false)).expect("fits");
        encode_upstream_head(&mut w, 502, &[], None, None).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].tag, generic::H_STATUS);
        assert_eq!(records[0].pod::<U32Rec>().expect("U32Rec").value, 201);
        assert_eq!(records[1].tag, generic::PAIR);
        assert_eq!(records[1].pair().expect("pair shape"), ("", &b""[..]));
        assert_eq!(records[1].body.len(), size_of::<PairRec>());
        let pin = records[2].pod::<FactRec>().expect("FactRec");
        assert_eq!(
            (records[2].tag, pin.key, pin.value),
            (generic::FACT, fact::FACT_TLS_PIN, 1)
        );
        let id = records[3].pod::<FactRec>().expect("FactRec");
        assert_eq!(
            (records[3].tag, id.key, id.value),
            (generic::FACT, fact::FACT_TLS_CLIENT_ID, 0)
        );
        // The second head: no pin and no client identity configured, so no facts.
        assert_eq!(records[4].tag, generic::H_STATUS);
        assert_eq!(records[4].pod::<U32Rec>().expect("U32Rec").value, 502);
    }

    #[test]
    fn committed_answers_are_one_record_each_in_answer_order() {
        let mut w = Reply::new();
        let answers = [
            (1, 1, 0, 0),
            (2, 2, 3, 0),
            (3, 0, 0, refused::R_RATE_LIMITED),
        ];
        encode_committed(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);
        for (rec, want) in records.iter().zip(answers) {
            assert_eq!(rec.tag, tag::COMMITTED);
            let got = rec.pod::<plane::CommittedRec>().expect("CommittedRec");
            assert_eq!((got.check, got.outcome, got.failed, got.status), want);
        }
    }

    #[test]
    fn trust_answers_carry_item_states_or_the_named_member() {
        let items = [
            TrustItem {
                name: "search",
                verdict: plane::DISTRUST_NONE,
                approved: Some([1; 32]),
                sighted: Some([2; 32]),
            },
            TrustItem {
                name: "fetch",
                verdict: plane::DISTRUST_NOT_APPROVED,
                approved: None,
                sighted: Some([3; 32]),
            },
        ];
        let answers = [
            TrustAnswer {
                check: 7,
                verdict: plane::DISTRUST_CHANGED,
                items: &items,
                named: "",
            },
            TrustAnswer {
                check: 8,
                verdict: plane::SIGNED_ALGORITHM,
                items: &[],
                named: "HS256",
            },
            TrustAnswer {
                check: 9,
                verdict: plane::SIGNED_VERIFIED,
                items: &[],
                named: "",
            },
        ];
        let mut w = Reply::new();
        encode_trust_answers(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);

        assert_eq!(records[0].tag, tag::TRUST_ANS);
        let (ans, tail) = records[0].pod_tail::<plane::TrustAns>().expect("TrustAns");
        assert_eq!((ans.check, ans.verdict), (7, plane::DISTRUST_CHANGED));
        let states = recs(tail);
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].tag, tag::TR_ITEM_STATE);
        let (first, rest) = states[0]
            .pod_tail::<plane::TrustItemState>()
            .expect("state");
        assert_eq!(
            (first.verdict, first.flags, first.name_len, first._r),
            (
                plane::DISTRUST_NONE,
                plane::TS_APPROVED | plane::TS_SIGHTED,
                6,
                0
            )
        );
        let mut want = b"search".to_vec();
        want.extend_from_slice(&[1; 32]);
        want.extend_from_slice(&[2; 32]);
        assert_eq!(rest, &want[..]);
        let (second, rest) = states[1]
            .pod_tail::<plane::TrustItemState>()
            .expect("state");
        assert_eq!(
            (second.verdict, second.flags, second.name_len),
            (plane::DISTRUST_NOT_APPROVED, plane::TS_SIGHTED, 5)
        );
        let mut want = b"fetch".to_vec();
        want.extend_from_slice(&[3; 32]);
        assert_eq!(rest, &want[..]);

        let (ans, tail) = records[1].pod_tail::<plane::TrustAns>().expect("TrustAns");
        assert_eq!(
            (ans.check, ans.verdict, tail),
            (8, plane::SIGNED_ALGORITHM, &b"HS256"[..])
        );
        let (ans, tail) = records[2].pod_tail::<plane::TrustAns>().expect("TrustAns");
        assert_eq!((ans.check, ans.verdict), (9, plane::SIGNED_VERIFIED));
        assert!(tail.is_empty());
    }

    #[test]
    fn a_named_member_is_cut_to_128_bytes_at_a_char_boundary() {
        let mut named = "x".repeat(127);
        named.push('ü');
        let answers = [TrustAnswer {
            check: 1,
            verdict: plane::SIGNED_CRITICAL,
            items: &[],
            named: &named,
        }];
        let mut w = Reply::new();
        encode_trust_answers(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        let (_, tail) = records[0].pod_tail::<plane::TrustAns>().expect("TrustAns");
        assert_eq!(tail, "x".repeat(127).as_bytes());
    }

    #[test]
    fn a_catalog_is_one_cat_model_text_per_model() {
        let mut w = Reply::new();
        encode_catalog(&mut w, &["gpt-5", "claude-opus", ""]).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(
            texts(&records, tag::CAT_MODEL),
            ["gpt-5", "claude-opus", ""]
        );
    }

    #[test]
    fn lookup_hits_carry_the_lookup_index_then_key_and_value() {
        let mut w = Reply::new();
        let hits: [(u32, &[u8], &[u8]); 2] = [(0, b"task/1", b"{\"s\":1}"), (2, b"k", b"")];
        encode_lookup_hits(&mut w, &hits).expect("fits");
        encode_chain_state(&mut w, 2, 9, 4).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);
        for (rec, (lookup, key, value)) in records.iter().zip(hits) {
            assert_eq!(rec.tag, tag::LOOKUP_HIT);
            let (hit, tail) = rec.pod_tail::<plane::LookupHit>().expect("LookupHit");
            assert_eq!(hit.lookup, lookup);
            assert_eq!(hit.key_len as usize, key.len());
            let (k, v) = tail.split_at(key.len());
            assert_eq!((k, v), (key, value));
        }
        assert_eq!(records[2].tag, tag::CHAIN_STATE);
        let state = records[2].pod::<plane::ChainState>().expect("ChainState");
        assert_eq!(
            (state.lookup, state._r, state.len, state.broken_at),
            (2, 0, 9, 4)
        );
    }

    #[test]
    fn entitle_and_judge_answers_are_one_record_each() {
        let mut w = Reply::new();
        encode_entitle_answers(&mut w, &[(4, true), (5, false)]).expect("fits");
        encode_judged(
            &mut w,
            &[(6, plane::DEST_ALLOWED), (7, plane::DEST_INTERNAL)],
        )
        .expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 4);
        let granted: Vec<_> = records[..2]
            .iter()
            .map(|rec| {
                assert_eq!(rec.tag, tag::ENTITLE_ANS);
                let ans = rec.pod::<plane::EntitleAns>().expect("EntitleAns");
                (ans.check, ans.granted)
            })
            .collect();
        assert_eq!(granted, [(4, 1), (5, 0)]);
        let judged: Vec<_> = records[2..]
            .iter()
            .map(|rec| {
                assert_eq!(rec.tag, tag::JUDGE_ANS);
                let ans = rec.pod::<plane::JudgeAns>().expect("JudgeAns");
                (ans.check, ans.verdict)
            })
            .collect();
        assert_eq!(
            judged,
            [(6, plane::DEST_ALLOWED), (7, plane::DEST_INTERNAL)]
        );
    }

    #[test]
    fn observed_answers_keep_intent_order_with_their_tails() {
        let answers = [
            ObservedAnswer::Scope {
                check: 1,
                status: plane::OBS_READY,
                scope: Some([9; 32]),
            },
            ObservedAnswer::Receipt {
                check: 2,
                status: plane::OBS_ACCEPTED,
                receipt: b"receipt-1",
            },
            ObservedAnswer::Scope {
                check: 3,
                status: plane::OBS_REFUSED,
                scope: None,
            },
        ];
        let mut w = Reply::new();
        encode_observed(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].tag, tag::OBS_SCOPE_ANS);
        let (ans, tail) = records[0]
            .pod_tail::<plane::ObsScopeAns>()
            .expect("ObsScopeAns");
        assert_eq!(
            (ans.check, ans.status, tail),
            (1, plane::OBS_READY, &[9u8; 32][..])
        );
        assert_eq!(records[1].tag, tag::OBS_RECEIPT);
        let (ans, tail) = records[1]
            .pod_tail::<plane::ObsReceipt>()
            .expect("ObsReceipt");
        assert_eq!(
            (ans.check, ans.status, tail),
            (2, plane::OBS_ACCEPTED, &b"receipt-1"[..])
        );
        assert_eq!(records[2].tag, tag::OBS_SCOPE_ANS);
        let (ans, tail) = records[2]
            .pod_tail::<plane::ObsScopeAns>()
            .expect("ObsScopeAns");
        assert_eq!((ans.check, ans.status), (3, plane::OBS_REFUSED));
        assert!(tail.is_empty());
    }

    #[test]
    fn work_answers_nest_the_reference_then_the_target() {
        let answers = [
            WorkAnswer {
                check: 1,
                status: 0,
                state: plane::WORK_LIVE,
                reference: "wk-1",
                target: "",
            },
            WorkAnswer {
                check: 2,
                status: 0,
                state: plane::WORK_LIVE,
                reference: "wk-1",
                target: "/v1beta/interactions/abc?alt=sse",
            },
            WorkAnswer {
                check: 3,
                status: refused::R_UNSUPPORTED,
                state: 0,
                reference: "",
                target: "",
            },
        ];
        let mut w = Reply::new();
        encode_work_answers(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);
        let want: [(u32, u32, u32, &[(u16, &str)]); 3] = [
            (1, 0, plane::WORK_LIVE, &[(tag::WK_REF, "wk-1")]),
            (
                2,
                0,
                plane::WORK_LIVE,
                &[
                    (tag::WK_REF, "wk-1"),
                    (tag::WK_TARGET, "/v1beta/interactions/abc?alt=sse"),
                ],
            ),
            (3, refused::R_UNSUPPORTED, 0, &[]),
        ];
        for (rec, (check, status, state, nested)) in records.iter().zip(want) {
            assert_eq!(rec.tag, tag::WORK_ANS);
            let (ans, tail) = rec.pod_tail::<plane::WorkAns>().expect("WorkAns");
            assert_eq!(
                (ans.check, ans.status, ans.state, ans._r),
                (check, status, state, 0)
            );
            let got: Vec<_> = recs(tail)
                .iter()
                .map(|r| (r.tag, r.text().expect("UTF-8")))
                .collect();
            assert_eq!(got, nested);
        }
    }

    #[test]
    fn the_provider_schema_is_at_most_one_text() {
        let mut none = Reply::new();
        none.put_text(tag::D_DIALECT, "anthropic").expect("fits");
        assert_eq!(
            decode_provider_schema(Records::new(none.as_bytes())),
            Ok(None)
        );

        let schema = r#"{"type":"object","properties":{"error_map":{"type":"object"}}}"#;
        let mut one = Reply::new();
        one.put_text(tag::D_DIALECT, "anthropic").expect("fits");
        one.put_text(tag::D_PROVIDER_SCHEMA, schema).expect("fits");
        assert_eq!(
            decode_provider_schema(Records::new(one.as_bytes())),
            Ok(Some(schema))
        );

        let mut two = Reply::new();
        two.put_text(tag::D_PROVIDER_SCHEMA, schema).expect("fits");
        two.put_text(tag::D_PROVIDER_SCHEMA, schema).expect("fits");
        assert_eq!(
            decode_provider_schema(Records::new(two.as_bytes())),
            Err(RecErr::Size)
        );

        let mut bad = Reply::new();
        bad.put(tag::D_PROVIDER_SCHEMA, &[0xff, 0xfe])
            .expect("fits");
        assert_eq!(
            decode_provider_schema(Records::new(bad.as_bytes())),
            Err(RecErr::Utf8)
        );
        // A framing error anywhere in the describe answer is the decoder's error.
        let mut cut = one.as_bytes().to_vec();
        cut.truncate(cut.len() - 8);
        assert_eq!(
            decode_provider_schema(Records::new(&cut)),
            Err(RecErr::Truncated)
        );
    }

    /// One D_DIALECT_AUTH item: TEXT dialect, TEXT presentation, then `fields`.
    fn row(
        w: &mut Reply,
        dialect: &str,
        present: &str,
        fields: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) {
        w.put_nested(tag::D_DIALECT_AUTH, |n| {
            n.put_text(generic::TEXT, dialect)?;
            n.put_text(generic::TEXT, present)?;
            fields(n)
        })
        .expect("fits");
    }

    /// One DA_FAMILY: DaFamilyRec, then nested TEXT prefix and TEXT header.
    fn family(n: &mut Nested<'_>, trim_start: u32, prefix: &str, header: &str) -> Result<(), Full> {
        let mut tail = Reply::new();
        tail.put_text(generic::TEXT, prefix)?;
        tail.put_text(generic::TEXT, header)?;
        let head = plane::DaFamilyRec { trim_start, _r: 0 };
        n.put_pod_tail(tag::DA_FAMILY, &head, tail.as_bytes())
    }

    /// plane-llm's six rows as IF §12.18 states them.
    fn plane_llm() -> Reply {
        let mut w = Reply::new();
        for dialect in [
            "anthropic",
            "gemini",
            "openai",
            "responses",
            "cohere",
            "bedrock",
        ] {
            w.put_text(tag::D_DIALECT, dialect).expect("fits");
        }
        w.put_text(tag::D_PROVIDER_SCHEMA, "{}").expect("fits");
        row(&mut w, "anthropic", PRESENT_HEADER, |n| {
            n.put_text(tag::DA_KEY_HEADER, "x-api-key")?;
            n.put_text(tag::DA_OWN_HEADER, "x-api-key")?;
            family(n, 1, "sk-ant-api", "x-api-key")?;
            family(n, 0, "sk-ant-oat", "")
        });
        row(&mut w, "gemini", PRESENT_HEADER, |n| {
            n.put_text(tag::DA_KEY_HEADER, "x-goog-api-key")?;
            n.put_text(tag::DA_OWN_HEADER, "x-goog-api-key")?;
            n.put_text(tag::DA_PASSTHROUGH_HEADER, "x-goog-api-key")
        });
        for dialect in ["openai", "responses", "cohere"] {
            row(&mut w, dialect, PRESENT_HEADER, |_| Ok(()));
        }
        row(&mut w, "bedrock", PRESENT_SIGN, |n| {
            n.put_text(tag::DA_SIGN_SERVICE, "bedrock")?;
            for label in [
                "bedrock-runtime",
                "bedrock-runtime-fips",
                "bedrock",
                "bedrock-fips",
            ] {
                n.put_text(tag::DA_REGION_AFTER, label)?;
            }
            n.put_text(tag::DA_REGION_DEFAULT, "us-east-1")
        });
        w
    }

    fn bearer(dialect: &str) -> DialectAuth<'_> {
        DialectAuth {
            dialect,
            present: Presentation::Header {
                key_header: None,
                own_header: None,
                passthrough_header: None,
                families: Vec::new(),
            },
        }
    }

    #[test]
    fn plane_llm_dialect_auth_rows_decode_typed_in_describe_order() {
        let w = plane_llm();
        let rows = decode_dialect_auth(Records::new(w.as_bytes())).expect("valid rows");
        let want = vec![
            DialectAuth {
                dialect: "anthropic",
                present: Presentation::Header {
                    key_header: Some("x-api-key"),
                    own_header: Some("x-api-key"),
                    passthrough_header: None,
                    families: vec![("sk-ant-api", "x-api-key", true), ("sk-ant-oat", "", false)],
                },
            },
            DialectAuth {
                dialect: "gemini",
                present: Presentation::Header {
                    key_header: Some("x-goog-api-key"),
                    own_header: Some("x-goog-api-key"),
                    passthrough_header: Some("x-goog-api-key"),
                    families: Vec::new(),
                },
            },
            bearer("openai"),
            bearer("responses"),
            bearer("cohere"),
            DialectAuth {
                dialect: "bedrock",
                present: Presentation::Sign {
                    service: "bedrock",
                    region_after: vec![
                        "bedrock-runtime",
                        "bedrock-runtime-fips",
                        "bedrock",
                        "bedrock-fips",
                    ],
                    region_default: "us-east-1",
                },
            },
        ];
        assert_eq!(rows, want);
        // An image that states no row decodes to none.
        let mut empty = Reply::new();
        empty.put_text(tag::D_DIALECT, "openai").expect("fits");
        assert_eq!(
            decode_dialect_auth(Records::new(empty.as_bytes())),
            Ok(Vec::new())
        );
    }

    #[test]
    fn an_owned_row_is_the_same_row_boxed() {
        let w = plane_llm();
        let rows = decode_dialect_auth(Records::new(w.as_bytes())).expect("valid rows");
        let anthropic = rows[0].to_owned();
        assert_eq!(
            anthropic,
            DialectAuthOwned {
                dialect: "anthropic".into(),
                present: PresentationOwned::Header {
                    key_header: Some("x-api-key".into()),
                    own_header: Some("x-api-key".into()),
                    passthrough_header: None,
                    families: vec![
                        ("sk-ant-api".into(), "x-api-key".into(), true),
                        ("sk-ant-oat".into(), "".into(), false),
                    ],
                },
            }
        );
        let bedrock = rows[5].to_owned();
        assert_eq!(
            bedrock,
            DialectAuthOwned {
                dialect: "bedrock".into(),
                present: PresentationOwned::Sign {
                    service: "bedrock".into(),
                    region_after: vec![
                        "bedrock-runtime".into(),
                        "bedrock-runtime-fips".into(),
                        "bedrock".into(),
                        "bedrock-fips".into(),
                    ],
                    region_default: "us-east-1".into(),
                },
            }
        );
    }

    /// A describe answer declaring `openai` with one row built by `build`.
    fn one_row(build: impl FnOnce(&mut Reply)) -> Result<Vec<DialectAuthOwned>, RecErr> {
        let mut w = Reply::new();
        w.put_text(tag::D_DIALECT, "openai").expect("fits");
        build(&mut w);
        decode_dialect_auth(Records::new(w.as_bytes()))
            .map(|rows| rows.iter().map(DialectAuth::to_owned).collect())
    }

    #[test]
    fn a_row_for_an_undeclared_dialect_or_a_second_row_is_refused() {
        assert_eq!(
            one_row(|w| row(w, "anthropic", PRESENT_HEADER, |_| Ok(()))),
            Err(RecErr::Size)
        );
        assert_eq!(
            one_row(|w| {
                row(w, "openai", PRESENT_HEADER, |_| Ok(()));
                row(w, "openai", PRESENT_HEADER, |_| Ok(()));
            }),
            Err(RecErr::Size)
        );
    }

    #[test]
    fn an_unknown_presentation_word_or_a_missing_head_is_refused() {
        assert_eq!(
            one_row(|w| row(w, "openai", "bearer", |_| Ok(()))),
            Err(RecErr::Size)
        );
        // Only the dialect: no presentation.
        assert_eq!(
            one_row(|w| w
                .put_nested(tag::D_DIALECT_AUTH, |n| n.put_text(generic::TEXT, "openai"))
                .expect("fits")),
            Err(RecErr::Size)
        );
        // The head is two TEXT records, not a DA_* field.
        assert_eq!(
            one_row(|w| w
                .put_nested(tag::D_DIALECT_AUTH, |n| {
                    n.put_text(generic::TEXT, "openai")?;
                    n.put_text(tag::DA_KEY_HEADER, "x-api-key")
                })
                .expect("fits")),
            Err(RecErr::Unknown(tag::DA_KEY_HEADER))
        );
    }

    #[test]
    fn a_field_of_the_other_presentation_is_an_unknown_tag() {
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_HEADER, |n| n
                .put_text(tag::DA_SIGN_SERVICE, "bedrock"))),
            Err(RecErr::Unknown(tag::DA_SIGN_SERVICE))
        );
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_SIGN, |n| {
                n.put_text(tag::DA_SIGN_SERVICE, "bedrock")?;
                n.put_text(tag::DA_REGION_DEFAULT, "us-east-1")?;
                n.put_text(tag::DA_KEY_HEADER, "x-api-key")
            })),
            Err(RecErr::Unknown(tag::DA_KEY_HEADER))
        );
        // A DA_* field outside any D_DIALECT_AUTH.
        assert_eq!(
            one_row(|w| w.put_text(tag::DA_KEY_HEADER, "x-api-key").expect("fits")),
            Err(RecErr::Unknown(tag::DA_KEY_HEADER))
        );
    }

    #[test]
    fn a_sign_row_needs_its_service_and_default_region_once() {
        fn sign(service: &[&str], default: &[&str]) -> Result<Vec<DialectAuthOwned>, RecErr> {
            one_row(|w| {
                row(w, "openai", PRESENT_SIGN, |n| {
                    for s in service {
                        n.put_text(tag::DA_SIGN_SERVICE, s)?;
                    }
                    n.put_text(tag::DA_REGION_AFTER, "bedrock-runtime")?;
                    for d in default {
                        n.put_text(tag::DA_REGION_DEFAULT, d)?;
                    }
                    Ok(())
                })
            })
        }
        assert!(sign(&["bedrock"], &["us-east-1"]).is_ok());
        assert_eq!(sign(&[], &["us-east-1"]), Err(RecErr::Size));
        assert_eq!(sign(&["bedrock"], &[]), Err(RecErr::Size));
        assert_eq!(
            sign(&["bedrock", "bedrock"], &["us-east-1"]),
            Err(RecErr::Size)
        );
        assert_eq!(
            sign(&["bedrock"], &["us-east-1", "eu-west-1"]),
            Err(RecErr::Size)
        );
    }

    #[test]
    fn every_text_keeps_the_charset_and_length_and_header_names_are_lowercase() {
        fn header(name: &str) -> Result<Vec<DialectAuthOwned>, RecErr> {
            one_row(|w| {
                row(w, "openai", PRESENT_HEADER, |n| {
                    n.put_text(tag::DA_KEY_HEADER, name)
                })
            })
        }
        assert!(header("x-api-key").is_ok());
        assert!(header(&"h".repeat(128)).is_ok());
        assert_eq!(header(&"h".repeat(129)), Err(RecErr::Size));
        assert_eq!(header("X-Api-Key"), Err(RecErr::Size));
        assert_eq!(header("x api key"), Err(RecErr::Size));
        assert_eq!(header(""), Err(RecErr::Size));
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_HEADER, |n| {
                n.put_text(tag::DA_KEY_HEADER, "x-api-key")?;
                n.put_text(tag::DA_KEY_HEADER, "x-api-key")
            })),
            Err(RecErr::Size)
        );
        // The signing texts are not header names: mixed case is in the charset.
        assert!(one_row(|w| row(w, "openai", PRESENT_SIGN, |n| {
            n.put_text(tag::DA_SIGN_SERVICE, "Bedrock")?;
            n.put_text(tag::DA_REGION_DEFAULT, "us-east-1")
        }))
        .is_ok());
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_SIGN, |n| {
                n.put_text(tag::DA_SIGN_SERVICE, "bed/rock")?;
                n.put_text(tag::DA_REGION_DEFAULT, "us-east-1")
            })),
            Err(RecErr::Size)
        );
    }

    #[test]
    fn a_family_is_a_trim_flag_a_prefix_and_a_header_or_bearer() {
        fn fam(trim: u32, prefix: &str, header: &str) -> Result<Vec<DialectAuthOwned>, RecErr> {
            one_row(|w| {
                row(w, "openai", PRESENT_HEADER, |n| {
                    family(n, trim, prefix, header)
                })
            })
        }
        assert!(fam(1, "sk-", "x-api-key").is_ok());
        assert!(fam(0, "sk-", "").is_ok());
        assert_eq!(fam(2, "sk-", ""), Err(RecErr::Size));
        assert_eq!(fam(0, "", "x-api-key"), Err(RecErr::Size));
        assert_eq!(fam(0, "sk-", "X-Api-Key"), Err(RecErr::Size));
        // A third nested record in a family.
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_HEADER, |n| {
                let mut tail = Reply::new();
                tail.put_text(generic::TEXT, "sk-")?;
                tail.put_text(generic::TEXT, "")?;
                tail.put_text(generic::TEXT, "extra")?;
                let head = plane::DaFamilyRec {
                    trim_start: 0,
                    _r: 0,
                };
                n.put_pod_tail(tag::DA_FAMILY, &head, tail.as_bytes())
            })),
            Err(RecErr::Unknown(generic::TEXT))
        );
        // A non-zero reserved word.
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_HEADER, |n| {
                let mut tail = Reply::new();
                tail.put_text(generic::TEXT, "sk-")?;
                tail.put_text(generic::TEXT, "")?;
                let head = plane::DaFamilyRec {
                    trim_start: 0,
                    _r: 1,
                };
                n.put_pod_tail(tag::DA_FAMILY, &head, tail.as_bytes())
            })),
            Err(RecErr::Reserved)
        );
    }
}
