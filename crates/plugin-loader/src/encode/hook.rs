// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Hook request encoders and describe decoders (IF §8.8).

use busbar_plugin_abi::kinds::hook::hook::{
    self as abi, B_HAS_SPEND, BudgetRec, COST_UNPRICED, CostTermRec, Points, tag,
};
use busbar_plugin_abi::records::{Full, RecErr, Records, Reply, Writer, tag as gtag};

use crate::ports::FactRef;
use crate::ports::hook::{BudgetIn, CandidateIn, CostTermIn, HookView};

/// The most D_WORD items one describe answer may carry.
const MAX_WORDS: usize = 8;
/// The longest strategy word, in bytes.
const MAX_WORD_LEN: usize = 32;

/// The D_POINTS mask bit of a decision point.
const fn point_bit(point: u32) -> u32 {
    1 << point
}

/// `[a-z][a-z0-9_-]{0,31}`.
fn word_ok(w: &str) -> bool {
    let b = w.as_bytes();
    b.len() <= MAX_WORD_LEN
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

/// Round 12: every D_WORD item of one describe answer (validated: word grammar, at most 8, POINT_ROUTE declared).
pub fn decode_words(describe: Records<'_>) -> Result<Vec<Box<str>>, RecErr> {
    let mut words: Vec<Box<str>> = Vec::new();
    let mut route = false;
    for rec in describe {
        let rec = rec?;
        match rec.tag {
            tag::D_POINTS => {
                let p: Points = rec.pod()?;
                route |= p.mask & point_bit(abi::POINT_ROUTE) != 0;
            }
            tag::D_WORD => {
                let w = rec.text()?;
                if words.len() == MAX_WORDS || !word_ok(w) {
                    return Err(RecErr::Size);
                }
                words.push(w.into());
            }
            _ => {}
        }
    }
    if !words.is_empty() && !route {
        return Err(RecErr::Size);
    }
    Ok(words)
}

/// The view core builds once per decision point: signals, candidates, and the optional parts.
/// Order: FACT/FACT_TEXT, CANDIDATE*, BUDGET*, CONVERSATION, BODY, ID_*.
pub fn encode_view(w: &mut impl Writer, v: &HookView<'_>) -> Result<(), Full> {
    for (key, fact) in v.signals {
        match *fact {
            FactRef::U(n) => w.put_fact(*key, n)?,
            FactRef::Text(s) => w.put_fact_text(*key, s)?,
        }
    }
    for c in v.candidates {
        candidate(w, c)?;
    }
    for b in v.budgets {
        budget(w, b)?;
    }
    if let Some(c) = v.conversation {
        w.put(gtag::CONVERSATION, c)?;
    }
    if let Some(b) = v.body {
        w.put(tag::BODY, b)?;
    }
    if let Some(ids) = v.identity {
        // Core-built ID_SUBJECT, ID_GROUP*, ID_CLAIM* records, copied record for record. A malformed
        // tail is core's own bug; it ends the copy rather than putting half a record on the wire.
        for rec in Records::new(ids) {
            let Ok(rec) = rec else { break };
            w.put(rec.tag, rec.body)?;
        }
    }
    Ok(())
}

fn candidate(w: &mut impl Writer, c: &CandidateIn<'_>) -> Result<(), Full> {
    // The tail is nested records after the Pod: a Pod head cannot ride `put_nested`.
    let mut tail = Reply::new();
    tail.put_text(tag::C_MODEL, c.model)?;
    tail.put_text(tag::C_PROVIDER, c.provider)?;
    if let Some(t) = c.tier {
        tail.put_text(tag::C_TIER, t)?;
    }
    for t in c.tags {
        tail.put_text(tag::C_TAG, t)?;
    }
    for t in c.cost_terms {
        cost_term(&mut tail, t)?;
    }
    w.put_pod_tail(tag::CANDIDATE, &c.rec, tail.as_bytes())
}

fn cost_term(w: &mut impl Writer, t: &CostTermIn<'_>) -> Result<(), Full> {
    let rec = CostTermRec {
        price_per_unit: t.price_per_unit.unwrap_or(f64::NAN),
        expected_units: t.expected_units,
        flags: if t.price_per_unit.is_none() {
            COST_UNPRICED
        } else {
            0
        },
        _r: 0,
    };
    w.put_pod_tail(tag::C_COST_TERM, &rec, t.class.as_bytes())
}

fn budget(w: &mut impl Writer, b: &BudgetIn<'_>) -> Result<(), Full> {
    let rec = BudgetRec {
        remaining_micros: b.remaining_micros,
        spend_micros_at_current_rate: b.spend_micros_at_current_rate.unwrap_or(0),
        window_start_s: b.window_start_s,
        flags: if b.spend_micros_at_current_rate.is_some() {
            B_HAS_SPEND
        } else {
            0
        },
        _r: 0,
    };
    let mut tail = Reply::new();
    tail.put_text(tag::B_ID, b.id)?;
    tail.put_text(tag::B_PERIOD, b.period)?;
    if let Some(g) = b.group {
        tail.put_text(tag::B_GROUP, g)?;
    }
    if let Some(p) = b.pool {
        tail.put_text(tag::B_POOL, p)?;
    }
    w.put_pod_tail(tag::BUDGET, &rec, tail.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::FactRef;
    use crate::ports::hook::{BudgetIn, CandidateIn, CostTermIn};
    use busbar_plugin_abi::kinds::hook::hook::{
        self as abi, BudgetRec, CandidateRec, CostTermRec, Points, tag,
    };
    use busbar_plugin_abi::records::{Reply, tag as gtag};

    fn describe(points: Option<u32>, words: &[&str]) -> Reply {
        let mut r = Reply::new();
        if let Some(mask) = points {
            r.put_pod(tag::D_POINTS, &Points { mask, _r: 0 }).unwrap();
        }
        for w in words {
            r.put_text(tag::D_WORD, w).unwrap();
        }
        r
    }

    fn route_mask() -> u32 {
        1 << abi::POINT_ROUTE
    }

    #[test]
    fn words_are_returned_in_describe_order() {
        let d = describe(Some(route_mask()), &["cheapest", "least_busy", "a-b_9"]);
        let got = decode_words(Records::new(d.as_bytes())).unwrap();
        let got: Vec<&str> = got.iter().map(|w| &**w).collect();
        assert_eq!(got, ["cheapest", "least_busy", "a-b_9"]);
    }

    #[test]
    fn no_word_needs_no_points() {
        let d = describe(None, &[]);
        assert!(decode_words(Records::new(d.as_bytes())).unwrap().is_empty());
    }

    #[test]
    fn a_word_without_route_declared_is_refused() {
        let d = describe(Some(1 << abi::POINT_NOTIFY), &["cheapest"]);
        assert!(decode_words(Records::new(d.as_bytes())).is_err());
        let d = describe(None, &["cheapest"]);
        assert!(decode_words(Records::new(d.as_bytes())).is_err());
    }

    #[test]
    fn nine_words_are_refused_and_eight_pass() {
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let d = describe(Some(route_mask()), &names[..8]);
        assert_eq!(decode_words(Records::new(d.as_bytes())).unwrap().len(), 8);
        let d = describe(Some(route_mask()), &names);
        assert!(decode_words(Records::new(d.as_bytes())).is_err());
    }

    #[test]
    fn the_word_grammar_is_enforced() {
        let long = "a".repeat(33);
        let ok = "a".repeat(32);
        for bad in ["", "Cheap", "1x", "-x", "a b", "a.b", long.as_str()] {
            let d = describe(Some(route_mask()), &[bad]);
            assert!(decode_words(Records::new(d.as_bytes())).is_err(), "{bad:?}");
        }
        let d = describe(Some(route_mask()), &[ok.as_str()]);
        assert!(decode_words(Records::new(d.as_bytes())).is_ok());
    }

    #[test]
    fn a_non_utf8_word_is_refused() {
        let mut d = describe(Some(route_mask()), &[]);
        d.put(tag::D_WORD, &[0xff, 0xfe]).unwrap();
        assert!(decode_words(Records::new(d.as_bytes())).is_err());
    }

    fn cand(index: u32, flags: u32) -> CandidateRec {
        CandidateRec {
            index,
            flags,
            context_max: 8000,
            cost_per_mtok_micros: 3,
            latency_ms: 40,
            budget_remaining_micros: -5,
            error_rate_ppm: 7,
            breaker: 0,
            rate_headroom_ppm: 9,
            _r: 0,
            weight: 2,
            available_concurrency: 4,
        }
    }

    fn recs(bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
        Records::new(bytes)
            .map(|r| {
                let r = r.unwrap();
                (r.tag, r.body.to_vec())
            })
            .collect()
    }

    #[test]
    fn a_view_is_signals_candidates_budgets_then_the_optional_parts() {
        let tags = ["t1", "t2"];
        let terms = [
            CostTermIn {
                class: "input",
                price_per_unit: Some(0.5),
                expected_units: 10.0,
            },
            CostTermIn {
                class: "output",
                price_per_unit: None,
                expected_units: 2.0,
            },
        ];
        let cands = [
            CandidateIn {
                rec: cand(0, abi::C_HAS_LATENCY | abi::C_HAS_COST),
                model: "m0",
                provider: "p0",
                tier: Some("gold"),
                tags: &tags,
                cost_terms: &terms,
            },
            CandidateIn {
                rec: cand(1, 0),
                model: "m1",
                provider: "p1",
                tier: None,
                tags: &[],
                cost_terms: &[],
            },
        ];
        let budgets = [
            BudgetIn {
                id: "b1",
                period: "day",
                group: Some("g"),
                pool: None,
                remaining_micros: 100,
                spend_micros_at_current_rate: Some(30),
                window_start_s: 1234,
            },
            BudgetIn {
                id: "b2",
                period: "month",
                group: None,
                pool: Some("pl"),
                remaining_micros: -1,
                spend_micros_at_current_rate: None,
                window_start_s: 5,
            },
        ];
        let signals = [
            (abi::S_ATTEMPT, FactRef::U(2)),
            (abi::S_POOL, FactRef::Text("main")),
        ];
        let v = HookView {
            signals: &signals,
            candidates: &cands,
            budgets: &budgets,
            conversation: Some(b"{\"messages\":[]}"),
            body: Some(b"raw"),
            identity: None,
        };
        let mut w = Reply::new();
        encode_view(&mut w, &v).unwrap();
        let got = recs(w.as_bytes());
        let order: Vec<u16> = got.iter().map(|r| r.0).collect();
        assert_eq!(
            order,
            [
                gtag::FACT,
                gtag::FACT_TEXT,
                tag::CANDIDATE,
                tag::CANDIDATE,
                tag::BUDGET,
                tag::BUDGET,
                gtag::CONVERSATION,
                tag::BODY
            ]
        );
        let all = Records::new(w.as_bytes())
            .map(|r| r.unwrap())
            .collect::<Vec<_>>();
        let (rec0, tail0) = all[2].pod_tail::<CandidateRec>().unwrap();
        assert_eq!(rec0.index, 0);
        assert_eq!(rec0.flags, abi::C_HAS_LATENCY | abi::C_HAS_COST);
        assert_eq!(rec0.weight, 2);
        let inner = recs(tail0);
        let inner_tags: Vec<u16> = inner.iter().map(|r| r.0).collect();
        assert_eq!(
            inner_tags,
            [
                tag::C_MODEL,
                tag::C_PROVIDER,
                tag::C_TIER,
                tag::C_TAG,
                tag::C_TAG,
                tag::C_COST_TERM,
                tag::C_COST_TERM
            ]
        );
        assert_eq!(inner[0].1, b"m0");
        assert_eq!(inner[2].1, b"gold");
        let nested0 = Records::new(tail0).collect::<Result<Vec<_>, _>>().unwrap();
        let (t0, c0) = nested0[5].pod_tail::<CostTermRec>().unwrap();
        assert_eq!(
            (t0.price_per_unit, t0.expected_units, t0.flags),
            (0.5, 10.0, 0)
        );
        assert_eq!(c0, b"input");
        let (t1, c1) = nested0[6].pod_tail::<CostTermRec>().unwrap();
        assert!(t1.price_per_unit.is_nan());
        assert_eq!(t1.flags, abi::COST_UNPRICED);
        assert_eq!(c1, b"output");
        // A candidate with no tier has no C_TIER record.
        let (_, tail1) = all[3].pod_tail::<CandidateRec>().unwrap();
        let t: Vec<u16> = recs(tail1).iter().map(|r| r.0).collect();
        assert_eq!(t, [tag::C_MODEL, tag::C_PROVIDER]);
        // Budgets.
        let (b1, bt1) = all[4].pod_tail::<BudgetRec>().unwrap();
        assert_eq!(
            (
                b1.remaining_micros,
                b1.spend_micros_at_current_rate,
                b1.window_start_s,
                b1.flags
            ),
            (100, 30, 1234, abi::B_HAS_SPEND)
        );
        let t: Vec<u16> = recs(bt1).iter().map(|r| r.0).collect();
        assert_eq!(t, [tag::B_ID, tag::B_PERIOD, tag::B_GROUP]);
        let (b2, bt2) = all[5].pod_tail::<BudgetRec>().unwrap();
        assert_eq!((b2.spend_micros_at_current_rate, b2.flags), (0, 0));
        let t: Vec<u16> = recs(bt2).iter().map(|r| r.0).collect();
        assert_eq!(t, [tag::B_ID, tag::B_PERIOD, tag::B_POOL]);
        assert_eq!(all[6].body, b"{\"messages\":[]}");
        assert_eq!(all[7].body, b"raw");
    }

    #[test]
    fn identity_records_follow_the_body() {
        let mut ident = Reply::new();
        ident.put_text(gtag::ID_SUBJECT, "alice").unwrap();
        ident.put_text(gtag::ID_GROUP, "staff").unwrap();
        let v = HookView {
            signals: &[],
            candidates: &[],
            budgets: &[],
            conversation: None,
            body: Some(b"x"),
            identity: Some(ident.as_bytes()),
        };
        let mut w = Reply::new();
        encode_view(&mut w, &v).unwrap();
        let got = recs(w.as_bytes());
        let order: Vec<u16> = got.iter().map(|r| r.0).collect();
        assert_eq!(order, [tag::BODY, gtag::ID_SUBJECT, gtag::ID_GROUP]);
        assert_eq!(got[1].1, b"alice");
    }

    #[test]
    fn an_empty_view_writes_nothing() {
        let v = HookView {
            signals: &[],
            candidates: &[],
            budgets: &[],
            conversation: None,
            body: None,
            identity: None,
        };
        let mut w = Reply::new();
        encode_view(&mut w, &v).unwrap();
        assert_eq!(w.len(), 0);
    }
}
