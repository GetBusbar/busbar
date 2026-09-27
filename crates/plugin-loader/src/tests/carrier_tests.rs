// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/carrier.rs`: the head accessor and the answer emit slots
//! answer only the handles the current dispatch on their thread issued, and state what the plane
//! said, untouched.

use super::*;

/// A stated answer head: the status and the headers.
type Stated = (Option<u16>, Vec<(Vec<u8>, Vec<u8>)>);

/// A stream that records what reached it; `open` false = the caller is gone.
struct Recorded {
    open: bool,
    head: Option<Stated>,
    body: Vec<u8>,
}

impl ReplyStream for Recorded {
    fn head(&mut self, status: Option<u16>, headers: &[(Vec<u8>, Vec<u8>)]) -> bool {
        self.head = Some((status, headers.to_vec()));
        self.open
    }
    fn chunk(&mut self, bytes: &[u8]) -> bool {
        self.body.extend_from_slice(bytes);
        self.open
    }
}

fn read(head: *const c_void, part: HeadPart, index: u32) -> (StatusClass, Vec<u8>, Vec<u8>) {
    let mut out = MaybeUninit::<HeadField>::uninit();
    let class = head_read(head, part as u8, index, &mut out);
    if class != StatusClass::Ok {
        return (class, Vec::new(), Vec::new());
    }
    // SAFETY: init-only-on-Ok; the ranges borrow the test's own head.
    let field = unsafe { out.assume_init() };
    // SAFETY: as above.
    unsafe { (class, field.name().to_vec(), field.value().to_vec()) }
}

#[test]
fn the_head_reads_back_every_part_the_caller_sent() {
    let headers: [(&[u8], &[u8]); 2] = [(b"x-one", b"1"), (b"accept", b"*/*")];
    let head = RequestHead {
        method: b"PATCH",
        path: b"/a/b",
        query: b"q=1&r=2",
        headers: &headers,
    };
    let ptr = core::ptr::from_ref(&head).cast::<c_void>();
    let _current = Current::enter(ptr, 0);
    assert_eq!(read(ptr, HeadPart::Method, 0).2, b"PATCH");
    assert_eq!(read(ptr, HeadPart::Path, 0).2, b"/a/b");
    assert_eq!(read(ptr, HeadPart::Query, 0).2, b"q=1&r=2");
    let (class, name, value) = read(ptr, HeadPart::Header, 1);
    assert_eq!(
        (class, &name[..], &value[..]),
        (StatusClass::Ok, &b"accept"[..], &b"*/*"[..])
    );
    assert_eq!(
        read(ptr, HeadPart::Header, 2).0,
        StatusClass::Gone,
        "past the last header"
    );
    let mut out = MaybeUninit::<HeadField>::uninit();
    assert_eq!(
        head_read(ptr, 9, 0, &mut out),
        StatusClass::Refused,
        "an unknown part"
    );
}

#[test]
fn a_head_the_current_dispatch_did_not_issue_is_refused() {
    let head = RequestHead {
        method: b"GET",
        path: b"/",
        query: b"",
        headers: &[],
    };
    let ptr = core::ptr::from_ref(&head).cast::<c_void>();
    assert_eq!(
        read(ptr, HeadPart::Method, 0).0,
        StatusClass::Refused,
        "no dispatch is current"
    );
    let other = RequestHead { ..head };
    let _current = Current::enter(core::ptr::from_ref(&other).cast(), 0);
    assert_eq!(
        read(ptr, HeadPart::Method, 0).0,
        StatusClass::Refused,
        "another dispatch's head"
    );
}

#[test]
fn the_answer_head_is_stated_once_and_only_as_the_plane_said_it() {
    let mut sink = Sink::new(None);
    let id = core::ptr::addr_of_mut!(sink) as usize as u64;
    let _current = Current::enter(core::ptr::null(), id);
    let fields = [
        HeadField::new(b"content-type", b"text/plain"),
        HeadField::new(b"x-a", b"b"),
    ];
    assert_eq!(
        emit_head(id + 8, 200, fields.as_ptr(), 2),
        StatusClass::Refused,
        "forged id"
    );
    assert_eq!(
        emit_head(id, 99, fields.as_ptr(), 2),
        StatusClass::Refused,
        "status < 100"
    );
    let bad = [HeadField::new(b"bad name", b"v")];
    assert_eq!(
        emit_head(id, 200, bad.as_ptr(), 1),
        StatusClass::Refused,
        "not a token"
    );
    let bad = [HeadField::new(b"x", b"a\r\nb")];
    assert_eq!(
        emit_head(id, 200, bad.as_ptr(), 1),
        StatusClass::Refused,
        "a control byte"
    );
    assert_eq!(emit_head(id, 429, fields.as_ptr(), 2), StatusClass::Ok);
    assert_eq!(
        emit_head(id, 200, fields.as_ptr(), 0),
        StatusClass::Refused,
        "a second head"
    );
    assert_eq!(
        emit_body(id, b"x".as_ptr(), 1),
        StatusClass::Refused,
        "no stream was offered"
    );
    assert_eq!(sink.status, Some(429));
    assert_eq!(
        sink.headers,
        vec![
            (b"content-type".to_vec(), b"text/plain".to_vec()),
            (b"x-a".to_vec(), b"b".to_vec())
        ]
    );
}

#[test]
fn the_first_chunk_commits_the_head_and_a_gone_caller_stops_the_plane() {
    let mut open = Recorded {
        open: true,
        head: None,
        body: Vec::new(),
    };
    {
        let mut sink = Sink::new(Some(&mut open));
        let id = core::ptr::addr_of_mut!(sink) as usize as u64;
        let _current = Current::enter(core::ptr::null(), id);
        let fields = [HeadField::new(b"x-a", b"b")];
        assert_eq!(emit_head(id, 207, fields.as_ptr(), 1), StatusClass::Ok);
        assert_eq!(emit_body(id, b"ab".as_ptr(), 2), StatusClass::Ok);
        assert_eq!(emit_body(id, b"cd".as_ptr(), 2), StatusClass::Ok);
        assert_eq!(
            emit_head(id, 200, fields.as_ptr(), 0),
            StatusClass::Refused,
            "body began"
        );
        assert!(sink.streamed);
    }
    assert_eq!(
        open.head,
        Some((Some(207), vec![(b"x-a".to_vec(), b"b".to_vec())]))
    );
    assert_eq!(open.body, b"abcd");

    let mut gone = Recorded {
        open: false,
        head: None,
        body: Vec::new(),
    };
    let mut sink = Sink::new(Some(&mut gone));
    let id = core::ptr::addr_of_mut!(sink) as usize as u64;
    let _current = Current::enter(core::ptr::null(), id);
    assert_eq!(emit_body(id, b"x".as_ptr(), 1), StatusClass::Gone);
    assert_eq!(
        emit_body(id, b"y".as_ptr(), 1),
        StatusClass::Gone,
        "and stays gone"
    );
}
