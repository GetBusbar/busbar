// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Lent` and `HostBuf`: host-lent bytes read without `unsafe`, host buffers filled to their
//! capacity with `needed` reported exactly. No FFI: each test lends from its own stack, as the
//! trampoline lends from its copy of the host's `in`.

use std::ptr;

use crate::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT, BLOB_JSON};
use crate::abi::mechanism::lifecycle::{OpenIn, ValidateIn};
use crate::abi::plane::{OnPieceIn, Span, UnitCount, UNITS_REPORTED};

use super::{HostBuf, Lent};

fn zeroed<T: crate::abi::sdk::door::AbiIn>() -> T {
    // SAFETY: `AbiIn` — every bit pattern, all-zero included, is a valid value.
    unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
}

fn lend<T>(v: &T) -> Lent<'_, T> {
    // SAFETY: every pointer the tests put in `v` points at live test memory for `'_`.
    unsafe { Lent::new(v) }
}

#[test]
fn a_blob_field_reads_as_its_bytes_and_an_absent_one_as_empty() {
    let json = br#"{"k":1}"#;
    let mut v: ValidateIn = zeroed();
    v.settings = Blob {
        ptr: json.as_ptr(),
        len: json.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    let lent = lend(&v);
    assert_eq!(lent.field(|i| &i.settings).bytes(), json);
    assert_eq!(
        lent.settings.fmt, BLOB_JSON,
        "plain fields read through Deref"
    );

    let absent: ValidateIn = zeroed();
    assert_eq!(lend(&absent).field(|i| &i.settings).bytes(), b"");
    // A NULL pointer with a length is still absent: nothing is read.
    let mut null_len: ValidateIn = zeroed();
    null_len.settings.len = 9;
    null_len.settings.fmt = BLOB_ABSENT;
    assert_eq!(lend(&null_len).field(|i| &i.settings).bytes(), b"");
}

#[test]
fn a_string_field_reads_as_bytes_and_as_utf8_or_refuses_bad_utf8() {
    let mut v: crate::abi::plane::PlaneOpenIn = zeroed();
    v.public_url = AbiStr {
        ptr: b"https://x".as_ptr(),
        len: 9,
    };
    let url = lend(&v).field(|i| &i.public_url);
    assert_eq!(url.bytes(), b"https://x");
    assert_eq!(url.as_str(), Ok("https://x"));

    let bad = [0xff_u8, 0xfe];
    v.public_url = AbiStr {
        ptr: bad.as_ptr(),
        len: bad.len(),
    };
    assert!(lend(&v).field(|i| &i.public_url).as_str().is_err());
}

#[test]
fn a_nested_field_is_reached_through_its_parent() {
    let mut v: crate::abi::plane::PlaneOpenIn = zeroed();
    v.open.settings = Blob {
        ptr: b"{}".as_ptr(),
        len: 2,
        fmt: BLOB_JSON,
        flags: 0,
    };
    let s = lend(&v).field(|i| &i.open).field(|o| &o.settings);
    assert_eq!(s.bytes(), b"{}");
}

#[test]
#[should_panic(expected = "not a field of the lent struct")]
fn a_picked_value_that_is_not_a_field_is_refused() {
    // RED: a Blob the plugin MADE, pointing anywhere, never reads as lent bytes.
    let forged: &'static Blob = Box::leak(Box::new(Blob {
        ptr: 0x10 as *const u8,
        len: 64,
        fmt: BLOB_JSON,
        flags: 0,
    }));
    let v: ValidateIn = zeroed();
    let _ = lend(&v).field(|_| forged).bytes();
}

#[test]
fn a_lent_list_lends_each_element() {
    let secrets = [
        Blob {
            ptr: b"a".as_ptr(),
            len: 1,
            fmt: 0,
            flags: 0,
        },
        Blob {
            ptr: b"bc".as_ptr(),
            len: 2,
            fmt: 0,
            flags: 0,
        },
    ];
    let mut v: OpenIn = zeroed();
    v.secrets = secrets.as_ptr();
    v.secrets_len = secrets.len();
    let list = lend(&v).secrets();
    assert_eq!(list.len(), 2);
    let got: Vec<&[u8]> = list.iter().map(|b| b.bytes()).collect();
    assert_eq!(got, [&b"a"[..], &b"bc"[..]]);
    assert!(list.get(2).is_none());

    let none: OpenIn = zeroed();
    assert!(lend(&none).secrets().is_empty());
}

fn piece(units: &mut [UnitCount], arena: &mut [u8], reply: &mut [u8]) -> OnPieceIn {
    let mut v: OnPieceIn = zeroed();
    v.units_buf = units.as_mut_ptr();
    v.units_cap = units.len();
    v.arena_buf = arena.as_mut_ptr();
    v.arena_cap = arena.len();
    v.reply_buf = reply.as_mut_ptr();
    v.reply_cap = reply.len();
    v
}

fn unit(amount: u64) -> UnitCount {
    UnitCount {
        class: 0,
        source: UNITS_REPORTED,
        amount,
    }
}

#[test]
fn a_host_buffer_that_fits_reports_written_and_no_need() {
    let mut units = [unit(0); 2];
    let (mut arena, mut reply) = ([0_u8; 8], [0_u8; 0]);
    let v = piece(&mut units, &mut arena, &mut reply);
    let mut buf = lend(&v).units_buf();
    assert_eq!(buf.cap(), 2);
    assert_eq!(buf.push(unit(5)), 0);
    assert_eq!(buf.push(unit(6)), 1);
    assert!(buf.fits());
    assert_eq!((buf.written(), buf.needed()), (2, 0));
    assert_eq!(buf.settle(false), (2, 0));
    assert_eq!(units[1].amount, 6);
}

#[test]
fn a_host_buffer_too_small_writes_to_cap_and_reports_needed_exactly() {
    let mut units = [unit(0); 1];
    let (mut arena, mut reply) = ([0_u8; 4], [0_u8; 0]);
    let v = piece(&mut units, &mut arena, &mut reply);
    let mut buf = lend(&v).units_buf();
    buf.push(unit(1));
    buf.push(unit(2));
    buf.push(unit(3));
    assert!(!buf.fits());
    // The short-buffer rule: FAILED, `written` 0, `needed` the full size — above the cap.
    assert_eq!((buf.written(), buf.needed()), (0, 3));
    assert_eq!(buf.settle(true), (0, 3));
    assert_eq!(units[0].amount, 1, "nothing is written past the capacity");

    let mut arena_buf = lend(&v).arena_buf();
    let s = arena_buf.span(b"abc");
    let t = arena_buf.span(b"defg");
    assert_eq!((s.offset, s.len, t.offset, t.len), (0, 3, 3, 4));
    assert_eq!((arena_buf.written(), arena_buf.needed()), (0, 7));
    assert_eq!(
        &arena, b"abcd",
        "the part that fits is written, never beyond"
    );
}

#[test]
fn in_a_short_answer_every_buffer_reports_its_full_size() {
    let mut units = [unit(0); 4];
    let (mut arena, mut reply) = ([0_u8; 2], [0_u8; 0]);
    let v = piece(&mut units, &mut arena, &mut reply);
    let mut u = lend(&v).units_buf();
    let mut a = lend(&v).arena_buf();
    u.push(unit(1));
    a.span(b"xyz");
    let short = !u.fits() || !a.fits();
    assert!(short);
    // The multi-buffer rule: every `needed` at its full size, nothing written.
    assert_eq!(u.settle(short), (0, 1));
    assert_eq!(a.settle(short), (0, 3));
}

#[test]
fn a_streamed_buffer_takes_what_fits_and_counts_only_that() {
    let mut units: [UnitCount; 0] = [];
    let (mut arena, mut reply) = ([0_u8; 0], [0_u8; 3]);
    let v = piece(&mut units, &mut arena, &mut reply);
    let mut r = lend(&v).reply_buf();
    assert_eq!(r.stream(b"hello"), 3);
    assert_eq!(r.stream(b"!"), 0);
    assert!(r.fits());
    assert_eq!(r.written(), 3);
    assert_eq!(&reply, b"hel");
}

#[test]
fn a_null_host_buffer_has_no_capacity_whatever_cap_says() {
    let mut v: OnPieceIn = zeroed();
    v.units_cap = 8;
    let mut buf = lend(&v).units_buf();
    assert_eq!(buf.cap(), 0);
    buf.push(unit(1));
    assert_eq!(buf.needed(), 1);
}

#[test]
fn an_arena_span_names_its_bytes_in_the_host_arena() {
    let mut units: [UnitCount; 0] = [];
    let (mut arena, mut reply) = ([0_u8; 8], [0_u8; 0]);
    let v = piece(&mut units, &mut arena, &mut reply);
    let mut a = lend(&v).arena_buf();
    a.span(b"ab");
    let s: Span = a.span(b"cd");
    let named = a.str_at(s);
    assert_eq!(named.len, 2);
    assert!(ptr::eq(named.ptr, arena[2..].as_ptr()));
}

#[test]
fn a_host_buf_from_nothing_is_empty() {
    // SAFETY: NULL with no capacity lends nothing.
    let mut b: HostBuf<'_, u8> = unsafe { HostBuf::new(ptr::null_mut(), 0) };
    assert_eq!(b.extend(b"x"), 0);
    assert_eq!(b.needed(), 1);
}
