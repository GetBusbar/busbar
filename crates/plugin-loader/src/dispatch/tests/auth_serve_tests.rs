// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::auth::{FIELD_QUERY, FIELD_SENSITIVE};

const NO_SPAN: FieldSpan = FieldSpan {
    name: Span { offset: 0, len: 0 },
    value: Span { offset: 0, len: 0 },
    flags: 0,
    _reserved: 0,
};

fn served() -> AuthServed {
    AuthServed::Fields {
        unit: UnitRef {
            id: 41,
            mac: 0xfeed,
        },
        fields: vec![
            ServedField {
                name: b"authorization".to_vec(),
                value: Wiped(b"Bearer sk-test".to_vec()),
                flags: FIELD_SENSITIVE,
            },
            ServedField {
                name: b"key".to_vec(),
                value: Wiped(b"q".to_vec()),
                flags: FIELD_QUERY,
            },
        ],
    }
}

fn answer_slot() -> AuthAnswer {
    AuthAnswer {
        size: 0,
        flow: 9,
        unit: UnitRef::NONE,
    }
}

/// An outbound answer round-trips through the store: the field bytes into the caller's `buf`, a
/// span per field with its flags, and the answer naming the unit and CONTINUE.
#[test]
fn an_outbound_answer_is_delivered_as_field_spans_and_the_unit() {
    let stored = stored(&served());
    let mut buf = vec![0_u8; 64];
    let mut spans = vec![NO_SPAN; 4];
    let mut answer = answer_slot();
    let into = AuthInto {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        spans: spans.as_mut_ptr(),
        spans_cap: spans.len(),
        answer: &mut answer,
    };
    // SAFETY: the test's own buffers, at their capacities.
    let d = unsafe { deliver(&stored, &into, "short") }.expect("fits");
    assert_eq!((d.outcome, d.items), (Outcome::Ready, 2));
    let text = |s: Span| &buf[s.offset as usize..(s.offset + s.len) as usize];
    assert_eq!(text(spans[0].name), b"authorization");
    assert_eq!(text(spans[0].value), b"Bearer sk-test");
    assert_eq!(spans[0].flags, FIELD_SENSITIVE);
    assert_eq!(text(spans[1].name), b"key");
    assert_eq!(spans[1].flags, FIELD_QUERY);
    assert_eq!(d.len as usize, b"authorization".len() + 14 + 3 + 1);
    assert_eq!(answer.flow, FLOW_CONTINUE);
    assert_eq!(
        answer.unit,
        UnitRef {
            id: 41,
            mac: 0xfeed
        }
    );
    assert_eq!(answer.size as usize, std::mem::size_of::<AuthAnswer>());
}

/// THE SHORT-BUFFER RULE: an answer that does not fit is FAILED with the field bytes' and the
/// fields' full sizes, nothing written; the trailer never counts.
#[test]
fn a_short_buffer_is_failed_with_the_full_sizes_and_nothing_written() {
    let stored = stored(&served());
    let mut buf = vec![0_u8; 4];
    let mut spans = vec![NO_SPAN; 1];
    let mut answer = answer_slot();
    let into = AuthInto {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        spans: spans.as_mut_ptr(),
        spans_cap: spans.len(),
        answer: &mut answer,
    };
    // SAFETY: the test's own buffers, at their capacities.
    let short = unsafe { deliver(&stored, &into, "short") }.expect_err("short");
    assert_eq!(short.outcome, Outcome::Failed);
    assert_eq!(short.needed_bytes, stored.value);
    assert_eq!(short.needed_items, 2);
    assert!(buf.iter().all(|b| *b == 0), "nothing written");
    assert_eq!(answer.flow, 9, "the answer slot is untouched");
}

/// A refusal is stored and delivered as REFUSED with its words, nothing written.
#[test]
fn a_refusal_is_refused_with_its_words() {
    let stored = stored(&AuthServed::Refused(OUTBOUND_REFUSED));
    let mut answer = answer_slot();
    let into = AuthInto {
        buf: std::ptr::null_mut(),
        cap: 0,
        spans: std::ptr::null_mut(),
        spans_cap: 0,
        answer: &mut answer,
    };
    // SAFETY: nothing is written on a refusal.
    let d = unsafe { deliver(&stored, &into, "short") }.expect("bare");
    assert_eq!((d.outcome, d.error), (Outcome::Refused, OUTBOUND_REFUSED));
    assert_eq!(answer.flow, 9);
}

/// An ask, a served line and an answer print no credential.
#[test]
fn outbound_material_never_prints() {
    let printed = format!("{:?}", served());
    assert!(!printed.contains("sk-test"), "{printed}");
}
