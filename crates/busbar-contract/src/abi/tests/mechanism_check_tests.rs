// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the shared answer-validator helpers: one per rule, each failing if its check is
//! removed.

use super::*;
use crate::abi::mechanism::call::Outcome::{Failed, Pending, Ready, Refused};

#[test]
fn a_ready_answer_writes_within_its_capacity() {
    assert_eq!(result(Ready, 4, 0, 4, 8, "t"), Ok(Filled::Written));
    assert_eq!(
        result(Ready, 5, 0, 4, 8, "t"),
        Err(fault(Rule::OverCap, "t"))
    );
}

#[test]
fn a_needed_size_on_any_outcome_but_failed_is_fault() {
    for o in [Ready, Pending, Refused] {
        assert_eq!(
            result(o, 0, 9, 4, 16, "t"),
            Err(fault(Rule::NeededNotFailed, "t"))
        );
    }
}

#[test]
fn a_short_answer_is_failed_over_cap_and_wrote_nothing() {
    assert_eq!(result(Failed, 0, 9, 4, 16, "t"), Ok(Filled::Short));
    assert_eq!(
        result(Failed, 0, 4, 4, 16, "t"),
        Err(fault(Rule::WastedRecall, "t"))
    );
    assert_eq!(
        result(Failed, 1, 9, 4, 16, "t"),
        Err(fault(Rule::WrittenOnShort, "t"))
    );
    assert_eq!(
        result(Failed, 0, 17, 4, 16, "t"),
        Err(fault(Rule::OverMax, "t"))
    );
}

#[test]
fn a_no_short_path_length_over_cap_is_fault() {
    assert_eq!(within(5, 4, "t"), Err(fault(Rule::OverCap, "t")));
    assert_eq!(within(4, 4, "t"), Ok(()));
}

#[test]
fn a_counted_null_list_is_fault() {
    assert_eq!(
        listed(std::ptr::null::<u8>(), 1, "t"),
        Err(fault(Rule::NullWithCount, "t"))
    );
    assert_eq!(listed(std::ptr::null::<u8>(), 0, "t"), Ok(()));
}

#[test]
fn indices_codes_and_bits_are_bounded() {
    assert_eq!(index(2, 2, "t"), Err(fault(Rule::IndexOutOfRange, "t")));
    assert_eq!(code(0, 1, 3, "t"), Err(fault(Rule::UnknownCode, "t")));
    assert_eq!(code(4, 1, 3, "t"), Err(fault(Rule::UnknownCode, "t")));
    assert_eq!(bits(4, 3, "t"), Err(fault(Rule::UnknownCode, "t")));
    assert_eq!(bits(3, 3, "t"), Ok(()));
}

#[test]
fn spans_are_absent_or_inside_with_checked_arithmetic() {
    assert_eq!(span(SPAN_ABSENT, 0, 4, "t"), Ok(()));
    assert_eq!(
        span(SPAN_ABSENT, 1, 4, "t"),
        Err(fault(Rule::SpanNotAbsent, "t"))
    );
    assert_eq!(span(2, 2, 4, "t"), Ok(()));
    assert_eq!(span(3, 2, 4, "t"), Err(fault(Rule::SpanOutOfBounds, "t")));
    assert_eq!(
        range(u64::MAX, 2, 4, "t"),
        Err(fault(Rule::SpanOutOfBounds, "t"))
    );
}

#[test]
fn a_weight_is_finite_and_not_negative() {
    assert_eq!(weight(f64::NAN, "t"), Err(fault(Rule::NotFinite, "t")));
    assert_eq!(weight(f64::INFINITY, "t"), Err(fault(Rule::NotFinite, "t")));
    assert_eq!(weight(-0.5, "t"), Err(fault(Rule::NotFinite, "t")));
    assert_eq!(weight(0.5, "t"), Ok(()));
}

#[test]
fn reported_checks_the_count_before_any_slice() {
    let buf = [7u32; 4];
    // SAFETY: `buf` is a host buffer of capacity 4.
    assert_eq!(unsafe { reported(buf.as_ptr(), 4, 4, "t") }, Ok(&buf[..]));
    // cap + 1, over a pointer no slice may ever be built from: refused before any read.
    let dangling = core::ptr::NonNull::<u32>::dangling().as_ptr().cast_const();
    assert_eq!(
        unsafe { reported(dangling, 5, 4, "t") },
        Err(fault(Rule::OverCap, "t"))
    );
    assert_eq!(
        unsafe { reported::<u32>(core::ptr::null(), 1, 4, "t") },
        Err(fault(Rule::NullWithCount, "t"))
    );
    assert_eq!(
        unsafe { reported::<u32>(core::ptr::null(), 0, 4, "t") },
        Ok(&[][..])
    );
}

#[test]
fn first_never_reads_past_the_buffer() {
    assert_eq!(first(&[1u8, 2], 3, "t"), Err(fault(Rule::OverCap, "t")));
    assert_eq!(first(&[1u8, 2], 2, "t"), Ok(&[1u8, 2][..]));
}

fn dim(written: u64, needed: u64, cap: u64, field: &'static str) -> Dim {
    Dim {
        written,
        needed,
        cap,
        max: 100,
        field,
    }
}

#[test]
fn a_multi_dimension_short_answer_needs_one_dimension_over_its_cap() {
    let one_short = [dim(0, 9, 4, "t.a"), dim(0, 3, 4, "t.b")];
    assert_eq!(
        results(Failed, "t", &one_short),
        Ok(Filled::Short),
        "a fitting dimension reports its size"
    );
    let both_fit = [dim(0, 4, 4, "t.a"), dim(0, 3, 4, "t.b")];
    assert_eq!(
        results(Failed, "t", &both_fit),
        Err(fault(Rule::WastedRecall, "t"))
    );
}

#[test]
fn a_multi_dimension_answer_keeps_every_other_rule() {
    assert_eq!(
        results(Ready, "t", &[dim(0, 0, 4, "t.a"), dim(0, 9, 4, "t.b")]),
        Err(fault(Rule::NeededNotFailed, "t.b"))
    );
    assert_eq!(
        results(Failed, "t", &[dim(0, 101, 4, "t.a")]),
        Err(fault(Rule::OverMax, "t.a"))
    );
    assert_eq!(
        results(Failed, "t", &[dim(1, 9, 4, "t.a"), dim(0, 0, 4, "t.b")]),
        Err(fault(Rule::WrittenOnShort, "t"))
    );
    assert_eq!(
        results(Ready, "t", &[dim(4, 0, 4, "t.a"), dim(5, 0, 4, "t.b")]),
        Err(fault(Rule::OverCap, "t.b"))
    );
    assert_eq!(
        results(Ready, "t", &[dim(4, 0, 4, "t.a"), dim(4, 0, 4, "t.b")]),
        Ok(Filled::Written)
    );
}

#[test]
fn a_string_counted_with_a_null_pointer_is_fault() {
    use crate::abi::mechanism::call::AbiStr;
    let bad = AbiStr {
        ptr: std::ptr::null(),
        len: 1,
    };
    let empty = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    assert_eq!(text(empty, "t"), Ok(()));
    assert_eq!(text(bad, "t"), Err(fault(Rule::NullWithCount, "t")));
    assert_eq!(
        texts(&[empty, bad], "t"),
        Err(fault(Rule::NullWithCount, "t"))
    );
}

// ── THE STATEMENT'S LISTS (the design's One Statement: marks, rewrites, sections, needs) ──────

use crate::abi::host::conn::connector::{Need, DIRECTION_INBOUND};
use crate::abi::mechanism::call::Blob;
use crate::abi::mechanism::door::{
    MarkWord, Rewrite, Section, MARK_BLOCKS, MARK_CATALOG, MARK_EPHEMERAL, MARK_ONE_INSTANCE,
    MARK_WORD_CARRIER, MARK_WORD_HOOK, REWRITE_ALIAS, REWRITE_KEY, REWRITE_SUGAR, SECTION_CONSUMED,
    SECTION_DECLARING,
};
use crate::abi::sdk::door::{abi_str, statement};

const NONE: AbiStr = AbiStr {
    ptr: core::ptr::null(),
    len: 0,
};

fn word(class: u32, w: &'static str) -> MarkWord {
    MarkWord {
        class,
        _reserved: 0,
        word: abi_str(w),
    }
}

fn rewrite(class: u32, from: &'static str, to: AbiStr) -> Rewrite {
    Rewrite {
        class,
        _reserved: 0,
        from: abi_str(from),
        to,
    }
}

fn section(name: &'static str, flags: u32) -> Section {
    Section {
        name: abi_str(name),
        flags,
        _reserved: 0,
    }
}

#[test]
fn the_flag_marks_are_single_distinct_bits_and_an_unknown_bit_is_fault() {
    let m = [MARK_ONE_INSTANCE, MARK_EPHEMERAL, MARK_CATALOG, MARK_BLOCKS];
    let mut seen = 0u64;
    for b in m {
        assert_eq!(b.count_ones(), 1);
        assert_eq!(seen & b, 0);
        seen |= b;
    }
    assert_eq!(seen, MARKS_KNOWN);
    assert_eq!(check_marks(MARKS_KNOWN, &[]), Ok(()));
    assert_eq!(
        check_marks(1 << 4, &[]),
        Err(fault(Rule::UnknownCode, "statement.marks"))
    );
}

#[test]
fn a_word_mark_has_a_known_class_and_a_word() {
    let ok = [
        word(MARK_WORD_HOOK, "cheapest"),
        word(MARK_WORD_CARRIER, "x-api-key"),
    ];
    assert_eq!(check_marks(0, &ok), Ok(()));
    assert_eq!(
        check_marks(0, &[word(3, "w")]),
        Err(fault(Rule::UnknownCode, "mark_word.class"))
    );
    assert_eq!(
        check_marks(0, &[word(0, "w")]),
        Err(fault(Rule::UnknownCode, "mark_word.class"))
    );
    let mut empty = word(MARK_WORD_HOOK, "w");
    empty.word = NONE;
    assert_eq!(
        check_marks(0, &[empty]),
        Err(fault(Rule::Missing, "mark_word.word"))
    );
}

#[test]
fn a_rewrite_moves_a_key_to_a_path_and_an_alias_or_sugar_names_nothing_else() {
    let ok = [
        rewrite(REWRITE_ALIAS, "tokens", NONE),
        rewrite(REWRITE_SUGAR, "sugar", NONE),
        rewrite(REWRITE_KEY, "key_ref", abi_str("key.ref")),
    ];
    assert_eq!(check_rewrites(&ok), Ok(()));
    assert_eq!(
        check_rewrites(&[rewrite(4, "x", NONE)]),
        Err(fault(Rule::UnknownCode, "rewrite.class"))
    );
    assert_eq!(
        check_rewrites(&[rewrite(REWRITE_ALIAS, "", NONE)]),
        Err(fault(Rule::Missing, "rewrite.from"))
    );
    assert_eq!(
        check_rewrites(&[rewrite(REWRITE_KEY, "key_ref", NONE)]),
        Err(fault(Rule::Missing, "rewrite.to"))
    );
    assert_eq!(
        check_rewrites(&[rewrite(REWRITE_ALIAS, "tokens", abi_str("x"))]),
        Err(fault(Rule::Contradiction, "rewrite.to"))
    );
}

#[test]
fn a_statement_has_at_most_one_declaring_section() {
    assert_eq!(check_statement_sections(&[]), Ok(()));
    assert_eq!(
        check_statement_sections(&[
            section("tools", SECTION_DECLARING),
            section("providers", SECTION_CONSUMED)
        ]),
        Ok(())
    );
    assert_eq!(
        check_statement_sections(&[
            section("a", SECTION_DECLARING),
            section("b", SECTION_DECLARING)
        ]),
        Err(fault(Rule::NotExactlyOne, "section.flags"))
    );
    assert_eq!(
        check_statement_sections(&[section("a", 8)]),
        Err(fault(Rule::UnknownCode, "section.flags"))
    );
    assert_eq!(
        check_statement_sections(&[section("", SECTION_CONSUMED)]),
        Err(fault(Rule::Missing, "section.name"))
    );
}

const WORDS: &[MarkWord] = &[MarkWord {
    class: MARK_WORD_HOOK,
    _reserved: 0,
    word: AbiStr {
        ptr: b"usage".as_ptr(),
        len: 5,
    },
}];

const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_INBOUND,
    egress_class: 0,
    transport: AbiStr {
        ptr: b"https".as_ptr(),
        len: 5,
    },
    auth: NONE,
    target_from: NONE,
    trust_from: NONE,
    details: Blob {
        ptr: core::ptr::null(),
        len: 0,
        fmt: 0,
        flags: 0,
    },
    timeout_ms: 0,
}];

#[test]
fn the_sdk_statement_states_no_marks_rewrites_sections_needs_paths_or_answers() {
    let st = statement("p", "1.0.0", 1);
    assert_eq!(st.marks, 0);
    assert!(st.mark_words.is_null() && st.mark_words_len == 0);
    assert!(st.rewrites.is_null() && st.rewrites_len == 0);
    assert!(st.sections.is_null() && st.sections_len == 0);
    assert!(st.needs.is_null() && st.needs_len == 0);
    assert_eq!(st.target_from.len, 0);
    assert_eq!(st.trust_from.len, 0);
    assert!(st.answers.is_null() && st.answers_len == 0);
    assert!(st.claims.is_null() && st.claims_len == 0);
    // SAFETY: every list is NULL with a zero count.
    assert_eq!(unsafe { check_statement(&st) }, Ok(()));
}

/// CLAIMS ARE A TRANSPORT'S FACT: a Statement of any other kind that states URL schemes is refused
/// at admit, so no store, plane or other kind can state a scheme Discover might read. RED: a plane
/// Statement claiming `https` is refused; the same claim on a transport Statement passes.
#[test]
fn a_statement_of_another_kind_stating_claims_is_refused() {
    const CLAIMS: &[AbiStr] = &[abi_str("https")];
    let mut st = statement("p", "1.0.0", 1);
    st.claims = CLAIMS.as_ptr();
    st.claims_len = CLAIMS.len();
    st.kind = crate::abi::mechanism::KindCode::Plane as u32;
    // SAFETY: the claims list is a `'static` array of its stated count.
    assert_eq!(
        unsafe { check_statement(&st) },
        Err(fault(Rule::Contradiction, "statement.claims"))
    );
    st.kind = crate::abi::mechanism::KindCode::Transport as u32;
    // SAFETY: as above.
    assert_eq!(unsafe { check_statement(&st) }, Ok(()));
}

#[test]
fn a_statement_list_is_checked_whole_and_a_null_list_with_a_count_is_fault() {
    let mut st = statement("p", "1.0.0", 1);
    st.mark_words = WORDS.as_ptr();
    st.mark_words_len = WORDS.len();
    st.needs = NEEDS.as_ptr();
    st.needs_len = NEEDS.len();
    // SAFETY: the lists are `'static` arrays of their stated counts.
    assert_eq!(unsafe { check_statement(&st) }, Ok(()));
    for (field, set) in [
        (
            "statement.mark_words",
            (|s: &mut Statement| s.mark_words = core::ptr::null()) as fn(&mut Statement),
        ),
        ("statement.rewrites", |s| s.rewrites_len = 1),
        ("statement.sections", |s| s.sections_len = 1),
        ("statement.needs", |s| s.needs = core::ptr::null()),
        ("statement.answers", |s| s.answers_len = 1),
        ("statement.claims", |s| {
            s.kind = crate::abi::mechanism::KindCode::Transport as u32;
            s.claims_len = 1;
        }),
        ("statement.target_from", |s| s.target_from.len = 1),
    ] {
        let mut bad = st;
        set(&mut bad);
        // SAFETY: a NULL list is refused before it is read; the others are as above.
        assert_eq!(
            unsafe { check_statement(&bad) },
            Err(fault(Rule::NullWithCount, field)),
            "{field}"
        );
    }
    let mut bad = st;
    bad.marks = 1 << 9;
    // SAFETY: as above.
    assert_eq!(
        unsafe { check_statement(&bad) },
        Err(fault(Rule::UnknownCode, "statement.marks"))
    );
}
