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

use crate::abi::host::conn::connector::{Need, DIRECTION_INBOUND, KEEP_NAMED};
use crate::abi::mechanism::call::Blob;
use crate::abi::mechanism::door::{
    MarkWord, Rewrite, Section, MARK_BLOCKS, MARK_CATALOG, MARK_EPHEMERAL, MARK_ONE_INSTANCE,
    MARK_WORD_CARRIER, MARK_WORD_HOOK, REWRITE_ALIAS, REWRITE_KEY, REWRITE_SUGAR,
    REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN, SECTION_CONSUMED,
    SECTION_DECLARING, SECTION_REQUIRED, SECTION_SELECTS,
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
        check_marks(0, &[word(8, "w")]),
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
        check_rewrites(&[rewrite(7, "x", abi_str("y"))]),
        Err(fault(Rule::UnknownCode, "rewrite.class"))
    );
    assert_eq!(
        check_rewrites(&[rewrite(0, "x", NONE)]),
        Err(fault(Rule::UnknownCode, "rewrite.class"))
    );
}

/// The secret-sugar rewrites a later contract reads (the sugar's settings key, its shown
/// placeholder, what its value names, its core role) are ACCEPTED by this one and grant nothing:
/// each names its `from` and its `to`, and a sugar may state the settings key it lands under, so a
/// plugin built for the later contract loads here unchanged (the two-step lockstep cure).
#[test]
fn the_later_sugar_rewrites_are_accepted_and_each_names_its_target() {
    let ok = [
        rewrite(REWRITE_SUGAR, "word", abi_str("key")),
        rewrite(REWRITE_SUGAR_SHOWN, "word", abi_str("PLACEHOLDER")),
        rewrite(REWRITE_SUGAR_NAMES, "word", abi_str("the thing it names")),
        rewrite(REWRITE_SUGAR_ROLE, "word", abi_str("fill")),
    ];
    assert_eq!(check_rewrites(&ok), Ok(()));
    for class in [REWRITE_SUGAR_SHOWN, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE] {
        assert_eq!(
            check_rewrites(&[rewrite(class, "word", NONE)]),
            Err(fault(Rule::Missing, "rewrite.to"))
        );
        assert_eq!(
            check_rewrites(&[rewrite(class, "", abi_str("x"))]),
            Err(fault(Rule::Missing, "rewrite.from"))
        );
    }
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
    keep_response_headers: core::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: core::ptr::null(),
    deny_response_headers_len: 0,
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

/// THE SELECTING SECTION (Law 7): a section whose presence uses the plane is a known bit beside
/// `SECTION_CONSUMED` and `SECTION_REQUIRED`, and redundant beside `SECTION_DECLARING` (a verb
/// selects its plane already). RED: before the bit was known, a consumed, required, selecting
/// section was refused as an unknown code.
#[test]
fn a_selecting_section_is_known_and_never_beside_the_declaring_one() {
    assert_eq!(
        check_statement_sections(&[
            section("pools", SECTION_DECLARING),
            section(
                "models",
                SECTION_CONSUMED | SECTION_REQUIRED | SECTION_SELECTS
            ),
        ]),
        Ok(())
    );
    assert_eq!(
        check_statement_sections(&[section("pools", SECTION_DECLARING | SECTION_SELECTS)]),
        Err(fault(Rule::Contradiction, "section.flags"))
    );
}

/// A SELECTING SECTION IS A PLANE'S FACT: a Statement of any other kind stating one is refused at
/// admit, never silently ignored. RED: a store Statement with a selecting section is refused; the
/// same section on a plane Statement passes.
#[test]
fn a_statement_of_another_kind_stating_a_selecting_section_is_refused() {
    const SECTIONS: &[Section] = &[Section {
        name: abi_str("models"),
        flags: SECTION_SELECTS,
        _reserved: 0,
    }];
    let mut st = statement("p", "1.0.0", 1);
    st.sections = SECTIONS.as_ptr();
    st.sections_len = SECTIONS.len();
    st.kind = crate::abi::mechanism::KindCode::Store as u32;
    // SAFETY: the sections list is a `'static` array of its stated count.
    assert_eq!(
        unsafe { check_statement(&st) },
        Err(fault(Rule::Contradiction, "statement.sections"))
    );
    st.kind = crate::abi::mechanism::KindCode::Plane as u32;
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

// ── THE STATEMENT LISTS' BOUNDS (contract audit M7: at most STATEMENT_LIST_MAX, never misaligned) ─

/// `STATEMENT_LIST_MAX + 1` answers, one past the cap.
const OVER_CAP: &[AbiStr] = &[abi_str("a"); STATEMENT_LIST_MAX + 1];

/// A Statement list above [`STATEMENT_LIST_MAX`] is refused before any entry is read, whichever
/// list states it; exactly the cap passes. RED: without the cap a plugin's stated count is walked
/// whole, and a count past its own data reads the host past it.
#[test]
fn a_statement_list_above_the_cap_is_refused_before_it_is_read() {
    let at_cap = &OVER_CAP[..STATEMENT_LIST_MAX];
    let mut st = statement("p", "1.0.0", 1);
    st.answers = at_cap.as_ptr();
    st.answers_len = at_cap.len();
    // SAFETY: the list is a `'static` array of its stated count.
    assert_eq!(unsafe { check_statement(&st) }, Ok(()));
    for (field, set) in [
        (
            "statement.answers",
            (|s: &mut Statement| {
                s.answers = OVER_CAP.as_ptr();
                s.answers_len = OVER_CAP.len();
            }) as fn(&mut Statement),
        ),
        ("statement.diag_ids", |s| {
            s.diag_ids = OVER_CAP.as_ptr();
            s.diag_ids_len = OVER_CAP.len();
        }),
        ("statement.secret_refs", |s| {
            s.secret_refs = OVER_CAP.as_ptr();
            s.secret_refs_len = OVER_CAP.len();
        }),
        ("statement.claims", |s| {
            s.kind = crate::abi::mechanism::KindCode::Transport as u32;
            s.claims = OVER_CAP.as_ptr();
            s.claims_len = OVER_CAP.len();
        }),
    ] {
        let mut bad = statement("p", "1.0.0", 1);
        set(&mut bad);
        // SAFETY: each list is a `'static` array of its stated count; the cap refuses it unread.
        assert_eq!(
            unsafe { check_statement(&bad) },
            Err(fault(Rule::OverMax, field)),
            "{field}"
        );
    }
}

/// A Statement list whose pointer is not aligned for its entry type is refused before a slice is
/// built over it (a slice over a misaligned pointer is undefined behaviour). RED: without the
/// alignment check the host builds the slice.
#[test]
fn a_misaligned_statement_list_is_refused_before_a_slice_is_built() {
    #[repr(C, align(16))]
    struct Raw([u8; 128]);
    let raw = Raw([0; 128]);
    let off = raw.0.as_ptr().wrapping_add(1);
    for (field, set) in [
        (
            "statement.answers",
            (|s: &mut Statement, p: *const u8| {
                s.answers = p.cast();
                s.answers_len = 1;
            }) as fn(&mut Statement, *const u8),
        ),
        ("statement.mark_words", |s, p| {
            s.mark_words = p.cast();
            s.mark_words_len = 1;
        }),
        ("statement.needs", |s, p| {
            s.needs = p.cast();
            s.needs_len = 1;
        }),
        ("statement.families", |s, p| {
            s.families = p.cast();
            s.families_len = 1;
        }),
    ] {
        let mut bad = statement("p", "1.0.0", 1);
        set(&mut bad, off);
        // SAFETY: the misaligned list is refused before it is read.
        assert_eq!(
            unsafe { check_statement(&bad) },
            Err(fault(Rule::Misaligned, field)),
            "{field}"
        );
    }
}

/// [`bounded`] alone: the cap and the alignment, NULL left to [`listed`].
#[test]
fn bounded_checks_the_cap_and_the_alignment_and_leaves_null_to_listed() {
    let ok: [u64; 2] = [0, 0];
    assert_eq!(bounded(ok.as_ptr(), 2, "t"), Ok(()));
    assert_eq!(bounded(core::ptr::null::<u64>(), 3, "t"), Ok(()));
    assert_eq!(
        bounded(ok.as_ptr(), STATEMENT_LIST_MAX + 1, "t"),
        Err(fault(Rule::OverMax, "t"))
    );
    let off = ok.as_ptr().cast::<u8>().wrapping_add(1).cast::<u64>();
    assert_eq!(bounded(off, 1, "t"), Err(fault(Rule::Misaligned, "t")));
    assert_eq!(bounded(off, 0, "t"), Ok(()));
}

/// THE ISSUED-CREDENTIAL SHAPE MARKS (row 159, K3#4): an auth row that reads host-held credentials
/// states the shape of the credential the host issues for it as word marks of five kind-neutral
/// classes (the public id's prefix, length and alphabet; the secret's length and alphabet), each a
/// known class the statement check admits, distinct from the hook and carrier classes. RED before
/// the classes exist.
#[test]
fn the_issued_credential_shape_marks_are_known_distinct_classes() {
    use crate::abi::mechanism::door::{
        MARK_WORD_ISSUED_ID_ALPHABET, MARK_WORD_ISSUED_ID_LENGTH, MARK_WORD_ISSUED_ID_PREFIX,
        MARK_WORD_ISSUED_SECRET_ALPHABET, MARK_WORD_ISSUED_SECRET_LENGTH,
    };
    let classes = [
        MARK_WORD_HOOK,
        MARK_WORD_CARRIER,
        MARK_WORD_ISSUED_ID_PREFIX,
        MARK_WORD_ISSUED_ID_LENGTH,
        MARK_WORD_ISSUED_ID_ALPHABET,
        MARK_WORD_ISSUED_SECRET_LENGTH,
        MARK_WORD_ISSUED_SECRET_ALPHABET,
    ];
    for (i, c) in classes.iter().enumerate() {
        assert_eq!(
            *c,
            i as u32 + 1,
            "the classes number on from 1 without a gap"
        );
    }
    let shape = [
        word(MARK_WORD_ISSUED_ID_PREFIX, "PFX"),
        word(MARK_WORD_ISSUED_ID_LENGTH, "20"),
        word(MARK_WORD_ISSUED_ID_ALPHABET, "ABC"),
        word(MARK_WORD_ISSUED_SECRET_LENGTH, "40"),
        word(MARK_WORD_ISSUED_SECRET_ALPHABET, "abc"),
    ];
    assert_eq!(check_marks(0, &shape), Ok(()));
}
